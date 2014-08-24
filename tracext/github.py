import fnmatch
import json
import os
import re

from genshi.builder import tag

from trac.config import ListOption, Option
from trac.core import Component, implements
from trac.util.translation import _
from trac.versioncontrol.api import is_default, NoSuchChangeset, RepositoryManager
from trac.versioncontrol.web_ui.changeset import ChangesetModule
from trac.web.api import IRequestHandler
from trac.web.auth import LoginModule


class GitHubLoginModule(LoginModule):

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'github_login'

    def get_navigation_items(self, req):
        if req.authname and req.authname != 'anonymous':
            # Use the same names as LoginModule to avoid duplicates.
            yield ('metanav', 'login', _('logged in as %(user)s',
                                         user=req.authname))
            yield ('metanav', 'logout',
                   tag.a(_('Logout'), href=req.href.github('logout')))
        else:
            # Use a different name from LoginModule to allow both in parallel.
            yield ('metanav', 'github_login',
                   tag.a(_('GitHub Login'), href=req.href.github('login')))

    # IRequestHandler methods

    def match_request(self, req):
        return re.match('/github/(login|oauth|logout)/?$', req.path_info)

    def process_request(self, req):
        if req.path_info.startswith('/github/login'):
            self._do_login(req)
        elif req.path_info.startswith('/github/oauth'):
            self._do_oauth(req)
        elif req.path_info.startswith('/github/logout'):
            self._do_logout(req)
        self._redirect_back(req)

    # Internal methods

    def _do_login(self, req):
        oauth = self._oauth_session(req)
        authorization_url, state = oauth.authorization_url(
            'https://github.com/login/oauth/authorize')
        req.session['oauth_state'] = state
        req.redirect(authorization_url)

    def _do_oauth(self, req):
        oauth = self._oauth_session(req)
        authorization_response = req.abs_href(req.path_info) + '?' + req.query_string
        client_secret = self._client_config('secret')
        oauth.fetch_token(
            'https://github.com/login/oauth/access_token',
            authorization_response=authorization_response,
            client_secret=client_secret)

        user = oauth.get('https://api.github.com/user').json()
        # Small hack to pass the username to _do_login.
        req.environ['REMOTE_USER'] = user['login']
        # Save other available values in the session.
        req.session.setdefault('name', user.get('name', ''))
        req.session.setdefault('email', user.get('email', ''))

        return super(GitHubLoginModule, self)._do_login(req)

    def _oauth_session(self, req):
        client_id = self._client_config('id')
        redirect_uri = req.abs_href.github('oauth')
        # Inner import to avoid a hard dependency on requests-oauthlib.
        from requests_oauthlib import OAuth2Session
        return OAuth2Session(client_id, redirect_uri=redirect_uri, scope=[])

    def _client_config(self, key):
        assert key in ('id', 'secret')
        value = self.config.get('github', 'client_' + key)
        if re.match('[0-9a-f]+', value):
            return value
        elif value.isupper():
            return os.environ.get(value, '')
        else:
            with open(value) as f:
                return f.read.strip()


class GitHubMixin(object):

    def get_gh_repo(self, reponame):
        key = 'repository' if is_default(reponame) else '%s.repository' % reponame
        return self.config.get('github', key)

    def get_branches(self, reponame):
        key = 'branches' if is_default(reponame) else '%s.branches' % reponame
        return self.config.getlist('github', key, sep=' ')


class GitHubBrowser(GitHubMixin, ChangesetModule):

    repository = Option('github', 'repository', '',
            doc="Repository name on GitHub (<user>/<project>)")

    # IRequestHandler methods

    def match_request(self, req):
        match = self._request_re.match(req.path_info)
        if match:
            rev, path = match.groups()
            req.args['rev'] = rev
            req.args['path'] = path or '/'
            return True

    def process_request(self, req):
        rev = req.args.get('rev')
        path = req.args.get('path')

        rm = RepositoryManager(self.env)
        reponame, repos, path = rm.get_repository_by_path(path)
        gh_repo = self.get_gh_repo(reponame)

        rev = repos.normalize_rev(rev)

        if path and path != '/':
            path = path.lstrip('/')
            # GitHub will s/blob/tree/ if the path is a directory
            url = 'https://github.com/%s/blob/%s/%s' % (gh_repo, rev, path)
        else:
            url = 'https://github.com/%s/commit/%s' % (gh_repo, rev)
        req.redirect(url)

    # ITimelineEventProvider methods

    def get_timeline_events(self, req, start, stop, filters):
        for event in super(GitHubBrowser, self).get_timeline_events(req, start, stop, filters):
            assert event[0] == 'changeset'
            viewable_changesets, show_location, show_files = event[3]
            filtered_changesets = []
            for cset, cset_resource, (reponame,) in viewable_changesets:
                branches = self.get_branches(reponame)
                if rev_in_branches(cset, branches):
                    filtered_changesets.append((cset, cset_resource, [reponame]))
            if filtered_changesets:
                cset = filtered_changesets[-1][0]
                yield ('changeset', cset.date, cset.author,
                        (filtered_changesets, show_location, show_files))


class GitHubPostCommitHook(GitHubMixin, Component):
    implements(IRequestHandler)

    branches = ListOption('github', 'branches', sep=' ',
            doc="Notify only commits on these branches to Trac")

    # IRequestHandler methods

    _request_re = re.compile(r"/github(/.*)?$")

    def match_request(self, req):
        match = self._request_re.match(req.path_info)
        if match:
            req.args['path'] = match.group(1) or '/'
            return True

    def process_request(self, req):
        if req.method != 'POST':
            msg = u'Endpoint is ready to accept GitHub notifications.\n'
            self.log.warning(u'Method not allowed (%s)' % req.method)
            req.send(msg.encode('utf-8'), 'text/plain', 405)

        event = req.get_header('X-GitHub-Event')
        if event == 'ping':
            payload = json.loads(req.read())
            req.send(payload['zen'].encode('utf-8'), 'text/plain', 200)
        elif event != 'push':
            msg = u'Only ping and push are supported\n'
            self.log.warning(msg.rstrip('\n'))
            req.send(msg.encode('utf-8'), 'text/plain', 400)

        path = req.args['path']

        rm = RepositoryManager(self.env)
        reponame, repos, path = rm.get_repository_by_path(path)

        if path != '/':
            msg = u'No such repository (%s)\n' % path
            self.log.warning(msg.rstrip('\n'))
            req.send(msg.encode('utf-8'), 'text/plain', 400)

        output = u'Running hook on %s\n' % (reponame or '(default)')

        output += u'* Updating clone\n'
        try:
            git = repos.git.repo             # GitRepository
        except AttributeError:
            git = repos.repos.git.repo       # GitCachedRepository
        git.remote('update', '--prune')

        # Ensure that repos.get_changeset can find the new changesets.
        output += u'* Synchronizing with clone\n'
        repos.sync()

        try:
            payload = json.loads(req.read())
            revs = [commit['id']
                    for commit in payload['commits'] if commit['distinct']]
        except (ValueError, KeyError):
            msg = u'Invalid payload\n'
            self.log.warning(msg.rstrip('\n'))
            req.send(msg.encode('utf-8'), 'text/plain', 400)

        branches = self.get_branches(reponame)
        added, skipped, unknown = classify_commits(revs, repos, branches)

        if added:
            output += u'* Adding %s\n' % describe_commits(added)
            # This is where Trac gets notified of the commits in the changeset
            rm.notify('changeset_added', reponame, added)

        if skipped:
            output += u'* Skipping %s\n' % describe_commits(skipped)

        if unknown:
            output += u'* Unknown %s\n' % describe_commits(unknown)
            self.log.error(u'Payload contains unknown %s',
                    describe_commits(unknown))

        for line in output.splitlines():
            self.log.debug(line)

        req.send(output.encode('utf-8'), 'text/plain', 200 if output else 204)


def classify_commits(revs, repos, branches):
    added, skipped, unknown = [], [], []
    for rev in revs:
        try:
            cset = repos.get_changeset(rev)
        except NoSuchChangeset:
            unknown.append(rev)
        else:
            if rev_in_branches(cset, branches):
                added.append(rev)
            else:
                skipped.append(rev)
    return added, skipped, unknown


def rev_in_branches(changeset, branches):
    if not branches:            # no branches filter configured
        return True
    return any(fnmatch.fnmatchcase(cset_branch, branch)
        for cset_branch, _ in changeset.get_branches() for branch in branches)


def describe_commits(revs):
    if len(revs) == 1:
        return u'commit %s' % revs[0]
    else:
        return u'commits %s' % u', '.join(revs)

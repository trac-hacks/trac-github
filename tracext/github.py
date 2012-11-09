import fnmatch
import json
import re

from trac.config import ListOption, Option
from trac.core import Component, implements
from trac.timeline.api import ITimelineEventProvider
from trac.versioncontrol.api import is_default, NoSuchChangeset, RepositoryManager
from trac.versioncontrol.web_ui.changeset import ChangesetModule
from trac.web.api import IRequestHandler


class GitHubMixin(object):

    def get_gh_repo(self, reponame):
        key = 'repository' if is_default(reponame) else '%s.repository' % reponame
        return self.config.get('github', key)

    def get_branches(self, reponame):
        key = 'branches' if is_default(reponame) else '%s.branches' % reponame
        return self.config.getlist('github', key, sep=' ')


class GitHubBrowser(GitHubMixin, ChangesetModule):
    implements(IRequestHandler, ITimelineEventProvider)

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
            # GitHub wraps the JSON payload in an urlencoded body and sends a
            # Content-Type: application/x-www-form-urlencoded header.
            # Unfortunately this triggers Trac's CSRF protection. Disable it.
            headers = [h for h in req._inheaders if h[0] != 'content-type']
            headers.append(('content-type', 'application/json'))
            req._inheaders = headers
            return True

    def process_request(self, req):
        if req.method != 'POST':
            msg = u'Method not allowed (%s)\n' % req.method
            self.log.warning(msg.rstrip('\n'))
            req.send(msg.encode('utf-8'), 'text/plain', 405)

        path = req.args['path']

        rm = RepositoryManager(self.env)
        reponame, repos, path = rm.get_repository_by_path(path)

        if path != '/':
            msg = u'No such repository (%s)\n' % path
            self.log.warning(msg.rstrip('\n'))
            req.send(msg.encode('utf-8'), 'text/plain', 400)

        output = u'Running hook on %s\n' % (reponame or '(default)')

        output += u'* Updating clone\n'
        repos.git.repo.remote('update', '--prune')
        output += u'* Synchronizing with clone\n'
        repos.git.sync()

        try:
            payload = json.loads(req.args['payload'])
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

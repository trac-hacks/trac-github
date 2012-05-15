import json
import re

from trac.config import BoolOption, Option
from trac.core import Component, implements
from trac.resource import ResourceNotFound
from trac.util.translation import _
from trac.versioncontrol.api import NoSuchChangeset, RepositoryManager
from trac.versioncontrol.web_ui.changeset import ChangesetModule
from trac.web.api import IRequestHandler


class GitHubBrowser(ChangesetModule):
    implements(IRequestHandler)

    gh_repo = Option('github', 'repository', '',
            doc="Repository name on GitHub (<user>/<project>)")

    def match_request(self, req):
        if not self.gh_repo:
            return super(GitHubBrowser, self).match_request(req)

        match = self._request_re.match(req.path_info)
        if match:
            rev, path = match.groups()
            req.args['rev'] = rev
            req.args['path'] = path or '/'
            return True

    def process_request(self, req):
        if not self.gh_repo:
            return super(GitHubBrowser, self).process_request(req)

        rev = req.args.get('rev')
        path = req.args.get('path')
        rm = RepositoryManager(self.env)
        reponame, repos, path = rm.get_repository_by_path(path)

        try:
            rev = repos.normalize_rev(rev)
        except NoSuchChangeset, e:
            raise ResourceNotFound(e.message, _('Invalid Changeset Number'))

        if path and path != '/':
            # GitHub will s/blob/tree/ if the path is a directory
            url = 'https://github.com/%s/blob/%s/%s' % (self.gh_repo, rev,
                    path.lstrip('/'))
        else:
            url = 'https://github.com/%s/commit/%s' % (self.gh_repo, rev)
        req.redirect(url)


class GitHubPostCommitHook(Component):
    implements(IRequestHandler)

    token = Option('github', 'token', '',
            doc="Secret token used in GitHub's Trac hook")
    autofetch = BoolOption('github', 'autofetch', 'enabled',
            doc="Fetch from GitHub after each commit")

    # IRequestHandler methods

    _request_re = re.compile(r"/github/([^/]+)(/.*)?$")

    def match_request(self, req):
        match = self._request_re.match(req.path_info)
        if match:
            token, path = match.groups()
            req.args['token'] = token
            req.args['path'] = path or '/'
            # GitHub sends Content-Type: application/x-www-form-urlencoded
            # which is wrong and triggers Trac's CSRF protection. Hack.
            headers = [h for h in req._inheaders if h[0] != 'content-type']
            headers.append(('content-type', 'application/json'))
            req._inheaders = headers
            return True

    def process_request(self, req):
        if req.method != 'POST':
            msg = u'Method not allowed (%s)\n' % req.method
            req.send(msg.encode('utf-8'), 'text/plain', 405)

        if req.args.get('token') != self.token:
            msg = u'Invalid token (%s)\n' % req.args.get('token')
            req.send(msg.encode('utf-8'), 'text/plain', 403)

        path = req.args.get('path', '/')
        rm = RepositoryManager(self.env)
        reponame, repos, path = rm.get_repository_by_path(path)

        output = u'Running hook on %s\n' % (reponame or '(default)')

        if self.autofetch:
            git = repos.git.repo
            output += u'* Running git fetch\n'
            output += git.fetch()
            output += u'* Updating references\n'
            remote_refs = git.for_each_ref(
                    "--format=%(refname)", "refs/remotes/origin").split()
            for remote_ref in remote_refs:
                local_ref = remote_ref.replace('remotes/origin', 'heads', 1)
                output += git.update_ref(local_ref, remote_ref)

        data = req.args.get('payload')
        if data:
            revs = [str(commit['id']) for commit in json.loads(data)]
            if revs:
                output += u'* Adding changesets %s\n' % u', '.join(revs)
                rm.notify('changeset_added', reponame, revs)

        req.send(output.encode('utf-8'), 'text/plain', 200 if output else 204)

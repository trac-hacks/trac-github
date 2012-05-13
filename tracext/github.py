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

    gh_repo = Option('github', 'repository', 'master',
            doc="Repository name on GitHub (<user>/<project>)")

    def match_request(self, req):
        if not self.gh_repo:
            return False

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

        try:
            rev = repos.normalize_rev(rev)
        except NoSuchChangeset, e:
            raise ResourceNotFound(e.message, _('Invalid Changeset Number'))

        if path:
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
    autopull = BoolOption('github', 'autopull', 'enabled',
            doc="Pull from GitHub after each commit")

    # IRequestHandler methods

    _request_re = re.compile(r"/github/([^/]+)(/.*)?$")

    def match_request(self, req):
        match = self._request_re.match(req.path_info)
        if match:
            token, path = match.groups()
            req.args['token'] = token
            req.args['path'] = path or '/'
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

        output = u'Running hook on %s\n' % reponame

        if self.autopull:
            output += u'Running git pull --ff-only\n'
            output += repos.git.repo.pull('--ff-only')

        data = req.args.get('payload')
        if data:
            revs = [str(commit['id']) for commit in json.loads(data)]
            if revs:
                output += u'Adding changesets %s\n' % u', '.join(revs)
                rm.notify('changeset_added', reponame, revs)

        req.send(output.encode('utf-8'), 'text/plain', 200 if output else 204)

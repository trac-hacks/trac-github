import json
import re

from trac.config import Option
from trac.core import Component, implements
from trac.resource import ResourceNotFound
from trac.util.translation import _
from trac.versioncontrol.api import is_default, NoSuchChangeset, RepositoryManager
from trac.versioncontrol.web_ui.changeset import ChangesetModule
from trac.web.api import IRequestHandler


class GitHubBrowser(ChangesetModule):
    implements(IRequestHandler)

    repository = Option('github', 'repository', '',
            doc="Repository name on GitHub (<user>/<project>)")

    def match_request(self, req):
        if not self.repository:                             # pragma: no cover
            return super(GitHubBrowser, self).match_request(req)

        match = self._request_re.match(req.path_info)
        if match:
            rev, path = match.groups()
            req.args['rev'] = rev
            req.args['path'] = path or '/'
            return True

    def process_request(self, req):
        if not self.repository:                             # pragma: no cover
            return super(GitHubBrowser, self).process_request(req)

        rev = req.args.get('rev')
        path = req.args.get('path')

        rm = RepositoryManager(self.env)
        reponame, repos, path = rm.get_repository_by_path(path)

        if is_default(reponame):
            gh_repo = self.config.get('github', 'repository')
        else:
            gh_repo = self.config.get('github', '%s.repository' % reponame)

        try:
            rev = repos.normalize_rev(rev)
        except NoSuchChangeset, e:
            raise ResourceNotFound(e.message, _('Invalid Changeset Number'))

        if path and path != '/':
            path = path.lstrip('/')
            # GitHub will s/blob/tree/ if the path is a directory
            url = 'https://github.com/%s/blob/%s/%s' % (gh_repo, rev, path)
        else:
            url = 'https://github.com/%s/commit/%s' % (gh_repo, rev)
        req.redirect(url)


class GitHubPostCommitHook(Component):
    implements(IRequestHandler)

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
        output += repos.git.repo.remote('update', '--prune')

        try:
            payload = json.loads(req.args['payload'])
            revs = [commit['id'] for commit in payload['commits']]
        except (ValueError, KeyError):
            msg = u'Invalid payload\n'
            self.log.warning(msg.rstrip('\n'))
            req.send(msg.encode('utf-8'), 'text/plain', 400)

        if revs:
            if len(revs) == 1:
                output += u'* Adding changeset %s\n' % revs[0]
            else:
                output += u'* Adding changesets %s\n' % u', '.join(revs)
            rm.notify('changeset_added', reponame, revs)

        for line in output.splitlines():
            self.log.debug(line)

        req.send(output.encode('utf-8'), 'text/plain', 200 if output else 204)

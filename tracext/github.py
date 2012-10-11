import fnmatch
import json
import re

from trac.config import ListOption, Option
from trac.core import Component, implements
from trac.resource import ResourceNotFound
from trac.util.translation import _
from trac.versioncontrol.api import is_default, NoSuchChangeset, RepositoryManager
from trac.versioncontrol.web_ui.changeset import ChangesetModule
from trac.web.api import IRequestHandler

def allow_revision(rev, repos, allowed_branches):
    rev_branches = repos.git.repo.branch('--contains', rev)
    rev_branches = [l[2:] for l in rev_branches.splitlines()]
    return any(fnmatch.fnmatchcase(rev_branch, branch) for rev_branch in rev_branches
                    for branch in allowed_branches)

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

        key = 'repository' if is_default(reponame) else '%s.repository' % reponame
        gh_repo = self.config.get('github', key)

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

    def get_timeline_events(self, req, start, stop, filters):
        rm = RepositoryManager(self.env)
        events = super(GitHubBrowser, self).get_timeline_events(req, start, stop, filters)
        for event in events:
            if event[0] != 'changeset':
                yield event
                continue
            allow = True
            for changeset in event[3][0]:
                reponame = changeset[2][0]
                repos = rm.get_repository(reponame)
                key = 'branches' if is_default(reponame) else '%s.branches' % reponame
                branches = self.config.getlist('github', key, sep=' ')
                if branches:
                    allow = allow and allow_revision(changeset[0].rev, repos, branches)
            if allow:
                yield event

class GitHubPostCommitHook(Component):
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

        key = 'branches' if is_default(reponame) else '%s.branches' % reponame
        branches = self.config.getlist('github', key, sep=' ')

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

        if branches:
            added_revs, skipped_revs = [], []
            for rev in revs:
                if allow_revision(rev, repos, branches):
                    added_revs.append(rev)
                else:
                    skipped_revs.append(rev)
        else:
            added_revs, skipped_revs = revs, []

        if added_revs:
            if len(added_revs) == 1:
                output += u'* Adding commit %s\n' % added_revs[0]
            else:
                output += u'* Adding commits %s\n' % u', '.join(added_revs)

            # This is where Trac gets notified of the commits in the changeset
            rm.notify('changeset_added', reponame, added_revs)

        if skipped_revs:
            if len(skipped_revs) == 1:
                output += u'* Skipping commit %s\n' % skipped_revs[0]
            else:
                output += u'* Skipping commits %s\n' % u', '.join(skipped_revs)

        for line in output.splitlines():
            self.log.debug(line)

        req.send(output.encode('utf-8'), 'text/plain', 200 if output else 204)

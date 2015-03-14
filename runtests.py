#!/usr/bin/env python

"""Functional tests for the Trac-GitHub plugin.

Trac's testing framework isn't well suited for plugins, so we NIH'd a bit.
"""

import ConfigParser
import glob
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import time
import unittest
import urllib2

from trac.env import Environment
from trac.ticket.model import Ticket


GIT = 'test-git-foo'
ALTGIT = 'test-git-bar'

ENV = 'test-trac-github'
CONF = '%s/conf/trac.ini' % ENV
URL = 'http://localhost:8765/%s/' % ENV
HEADERS = {'Content-Type': 'application/json', 'X-GitHub-Event': 'push'}

COVERAGE = False
SHOW_LOG = False


class HttpNoRedirectHandler(urllib2.HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib2.HTTPError(req.get_full_url(), code, msg, headers, fp)

urllib2.install_opener(urllib2.build_opener(HttpNoRedirectHandler()))


class TracGitHubTests(unittest.TestCase):

    cached_git = False

    @classmethod
    def setUpClass(cls):
        cls.createGitRepositories()
        cls.createTracEnvironment()
        cls.startTracd()
        cls.env = Environment(ENV)

    @classmethod
    def tearDownClass(cls):
        cls.env.shutdown()
        cls.stopTracd()
        cls.removeTracEnvironment()
        cls.removeGitRepositories()

    @classmethod
    def createGitRepositories(cls):
        subprocess.check_output(['git', 'init', GIT])
        subprocess.check_output(['git', 'init', ALTGIT])
        cls.makeGitCommit(GIT, 'README', 'default git repository\n')
        cls.makeGitCommit(ALTGIT, 'README', 'alternative git repository\n')
        subprocess.check_output(['git', 'clone', '--quiet', '--mirror', GIT, '%s-mirror' % GIT])
        subprocess.check_output(['git', 'clone', '--quiet', '--mirror', ALTGIT, '%s-mirror' % ALTGIT])

    @classmethod
    def removeGitRepositories(cls):
        shutil.rmtree(GIT)
        shutil.rmtree(ALTGIT)
        shutil.rmtree('%s-mirror' % GIT)
        shutil.rmtree('%s-mirror' % ALTGIT)

    @classmethod
    def createTracEnvironment(cls):
        subprocess.check_output(['trac-admin', ENV, 'initenv',
                'Trac - GitHub tests', 'sqlite:db/trac.db'])
        subprocess.check_output(['trac-admin', ENV, 'permission',
                'add', 'anonymous', 'TRAC_ADMIN'])

        conf = ConfigParser.ConfigParser()
        with open(CONF, 'rb') as fp:
            conf.readfp(fp)

        conf.add_section('components')
        conf.set('components', 'trac.versioncontrol.web_ui.browser.BrowserModule', 'disabled')
        conf.set('components', 'trac.versioncontrol.web_ui.changeset.ChangesetModule', 'disabled')
        conf.set('components', 'trac.versioncontrol.web_ui.log.LogModule', 'disabled')
        conf.set('components', 'trac.versioncontrol.svn_fs.*', 'disabled')      # avoid spurious log messages
        conf.set('components', 'tracext.git.*', 'enabled')                      # Trac 0.12.4
        conf.set('components', 'tracext.github.*', 'enabled')
        conf.set('components', 'tracopt.ticket.commit_updater.*', 'enabled')
        conf.set('components', 'tracopt.versioncontrol.git.*', 'enabled')       # Trac 1.0

        if cls.cached_git:
            conf.add_section('git')
            conf.set('git', 'cached_repository', 'true')
            conf.set('git', 'persistent_cache', 'true')

        conf.add_section('github')
        conf.set('github', 'repository', 'aaugustin/trac-github')
        conf.set('github', 'alt.repository', 'follower/trac-github')
        conf.set('github', 'alt.branches', 'master stable/*')

        if SHOW_LOG:
            # The [logging] section already exists in the default trac.ini file.
            conf.set('logging', 'log_type', 'stderr')

        conf.add_section('repositories')
        conf.set('repositories', '.dir', os.path.realpath('%s-mirror' % GIT))
        conf.set('repositories', '.type', 'git')
        conf.set('repositories', 'alt.dir', os.path.realpath('%s-mirror' % ALTGIT))
        conf.set('repositories', 'alt.type', 'git')

        with open(CONF, 'wb') as fp:
            conf.write(fp)

        subprocess.check_output(['trac-admin', ENV, 'repository', 'resync', ''])
        subprocess.check_output(['trac-admin', ENV, 'repository', 'resync', 'alt'])

    @classmethod
    def removeTracEnvironment(cls):
        shutil.rmtree(ENV)

    @classmethod
    def startTracd(cls):
        if COVERAGE:
            tracd = ['coverage', 'run', '--append', '--branch',
                     '--source=tracext.github',
                     subprocess.check_output(['which', 'tracd']).strip()]

        else:
            tracd = ['tracd']
        if SHOW_LOG:
            kwargs = {}
        else:
            kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.tracd = subprocess.Popen(tracd + ['--port', '8765', ENV], **kwargs)

        while True:
            try:
                urllib2.urlopen(URL)
            except urllib2.URLError:
                time.sleep(0.1)
            else:
                break

    @classmethod
    def stopTracd(cls):
        cls.tracd.send_signal(signal.SIGINT)
        cls.tracd.wait()

    @staticmethod
    def makeGitBranch(repo, branch):
        subprocess.check_output(['git', '--git-dir=%s/.git' % repo, 'branch', branch])

    @staticmethod
    def makeGitCommit(repo, path, content, message='edit', branch='master'):
        if branch != 'master':
            subprocess.check_output(['git', '--git-dir=%s/.git' % repo, 'checkout', branch],
                    stderr=subprocess.PIPE)
        path = os.path.join(repo, path)
        with open(path, 'wb') as fp:
            fp.write(content)
        subprocess.check_output(['git', '--git-dir=%s/.git' % repo, 'add', path])
        subprocess.check_output(['git', '--git-dir=%s/.git' % repo, 'commit', '-m', message])
        if branch != 'master':
            subprocess.check_output(['git', '--git-dir=%s/.git' % repo, 'checkout', 'master'],
                    stderr=subprocess.PIPE)

    @staticmethod
    def openGitHubHook(n=1, reponame=''):
        # See https://developer.github.com/v3/activity/events/types/#pushevent
        # We don't reproduce the entire payload, only what the plugin needs.
        url = (URL + 'github/' + reponame) if reponame else URL + 'github'
        repo = {'': GIT, 'alt': ALTGIT}[reponame]

        commits = []
        log = subprocess.check_output(['git', '--git-dir=%s/.git' % repo, 'log',
                '-%d' % n, '--branches', '--format=oneline', '--topo-order'])
        for line in log.splitlines():
            id, _, message = line.partition(' ')
            commits.append({'id': id, 'message': message, 'distinct': True})
        payload = {'commits': commits}
        request = urllib2.Request(url, json.dumps(payload), HEADERS)
        return urllib2.urlopen(request)


class GitHubBrowserTests(TracGitHubTests):

    def testLinkToChangeset(self):
        self.makeGitCommit(GIT, 'myfile', 'for browser tests')
        changeset = self.openGitHubHook().read().rstrip()[-40:]
        try:
            urllib2.urlopen(URL + 'changeset/' + changeset)
        except urllib2.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            self.assertEqual(exc.headers['Location'],
                    'https://github.com/aaugustin/trac-github/commit/%s' % changeset)
        else:
            self.fail("URL didn't redirect")

    def testAlternateLinkToChangeset(self):
        self.makeGitCommit(ALTGIT, 'myfile', 'for browser tests')
        changeset = self.openGitHubHook(1, 'alt').read().rstrip()[-40:]
        try:
            urllib2.urlopen(URL + 'changeset/' + changeset + '/alt')
        except urllib2.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            self.assertEqual(exc.headers['Location'],
                    'https://github.com/follower/trac-github/commit/%s' % changeset)
        else:
            self.fail("URL didn't redirect")

    def testLinkToPath(self):
        self.makeGitCommit(GIT, 'myfile', 'for more browser tests')
        changeset = self.openGitHubHook().read().rstrip()[-40:]
        try:
            urllib2.urlopen(URL + 'changeset/' + changeset + '/myfile')
        except urllib2.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            self.assertEqual(exc.headers['Location'],
                    'https://github.com/aaugustin/trac-github/blob/%s/myfile' % changeset)
        else:
            self.fail("URL didn't redirect")

    def testAlternateLinkToPath(self):
        self.makeGitCommit(ALTGIT, 'myfile', 'for more browser tests')
        changeset = self.openGitHubHook(1, 'alt').read().rstrip()[-40:]
        try:
            urllib2.urlopen(URL + 'changeset/' + changeset + '/alt/myfile')
        except urllib2.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            self.assertEqual(exc.headers['Location'],
                    'https://github.com/follower/trac-github/blob/%s/myfile' % changeset)
        else:
            self.fail("URL didn't redirect")

    def testBadChangeset(self):
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 404: Not Found$'):
            urllib2.urlopen(URL + 'changeset/1234567890')

    def testBadUrl(self):
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 404: Not Found$'):
            urllib2.urlopen(URL + 'changesetnosuchurl')

    def testTimelineFiltering(self):
        self.makeGitBranch(GIT, 'stable/2.0')
        self.makeGitBranch(GIT, 'unstable/2.0')
        self.makeGitBranch(ALTGIT, 'stable/2.0')
        self.makeGitBranch(ALTGIT, 'unstable/2.0')
        self.makeGitCommit(GIT, 'myfile', 'timeline 1\n', 'msg 1')
        self.makeGitCommit(GIT, 'myfile', 'timeline 2\n', 'msg 2', 'stable/2.0')
        self.makeGitCommit(GIT, 'myfile', 'timeline 3\n', 'msg 3', 'unstable/2.0')
        self.makeGitCommit(ALTGIT, 'myfile', 'timeline 4\n', 'msg 4')
        self.makeGitCommit(ALTGIT, 'myfile', 'timeline 5\n', 'msg 5', 'stable/2.0')
        self.makeGitCommit(ALTGIT, 'myfile', 'timeline 6\n', 'msg 6', 'unstable/2.0')
        self.openGitHubHook(3)
        self.openGitHubHook(3, 'alt')
        html = urllib2.urlopen(URL + 'timeline').read()
        self.assertTrue('msg 1' in html)
        self.assertTrue('msg 2' in html)
        self.assertTrue('msg 3' in html)
        self.assertTrue('msg 4' in html)
        self.assertTrue('msg 5' in html)
        self.assertFalse('msg 6' in html)


class GitHubPostCommitHookTests(TracGitHubTests):

    def testDefaultRepository(self):
        output = self.openGitHubHook(0).read()
        self.assertEqual(output, "Running hook on (default)\n"
                                 "* Updating clone\n"
                                 "* Synchronizing with clone\n")

    def testAlternativeRepository(self):
        output = self.openGitHubHook(0, 'alt').read()
        self.assertEqual(output, "Running hook on alt\n"
                                 "* Updating clone\n"
                                 "* Synchronizing with clone\n")

    def testCommit(self):
        self.makeGitCommit(GIT, 'foo', 'foo content\n')
        output = self.openGitHubHook().read()
        self.assertRegexpMatches(output, r"Running hook on \(default\)\n"
                                         r"\* Updating clone\n"
                                         r"\* Synchronizing with clone\n"
                                         r"\* Adding commit [0-9a-f]{40}\n")

    def testMultipleCommits(self):
        self.makeGitCommit(GIT, 'bar', 'bar content\n')
        self.makeGitCommit(GIT, 'bar', 'more bar content\n')
        output = self.openGitHubHook(2).read()
        self.assertRegexpMatches(output, r"Running hook on \(default\)\n"
                                         r"\* Updating clone\n"
                                         r"\* Synchronizing with clone\n"
                                         r"\* Adding commits [0-9a-f]{40}, [0-9a-f]{40}\n")

    def testCommitOnBranch(self):
        self.makeGitBranch(ALTGIT, 'stable/1.0')
        self.makeGitCommit(ALTGIT, 'stable', 'stable branch\n', branch='stable/1.0')
        self.makeGitBranch(ALTGIT, 'unstable/1.0')
        self.makeGitCommit(ALTGIT, 'unstable', 'unstable branch\n', branch='unstable/1.0')
        output = self.openGitHubHook(2, 'alt').read()
        self.assertRegexpMatches(output, r"Running hook on alt\n"
                                         r"\* Updating clone\n"
                                         r"\* Synchronizing with clone\n"
                                         r"\* Adding commit [0-9a-f]{40}\n"
                                         r"\* Skipping commit [0-9a-f]{40}\n")

    def testUnknownCommit(self):
        # Emulate self.openGitHubHook to use a non-existent commit id
        random_id = ''.join(random.choice('0123456789abcdef') for _ in range(40))
        payload = {'commits': [{'id': random_id, 'message': '', 'distinct': True}]}
        request = urllib2.Request(URL + 'github', json.dumps(payload), HEADERS)
        output = urllib2.urlopen(request).read()
        self.assertRegexpMatches(output, r"Running hook on \(default\)\n"
                                         r"\* Updating clone\n"
                                         r"\* Synchronizing with clone\n"
                                         r"\* Unknown commit [0-9a-f]{40}\n")

    def testNotification(self):
        ticket = Ticket(self.env)
        ticket['summary'] = 'I need a commit!'
        ticket['status'] = 'new'
        ticket_id = ticket.insert()

        ticket = Ticket(self.env, ticket_id)
        self.assertEqual(ticket['status'], 'new')
        self.assertEqual(ticket['resolution'], '')

        message = "Fix #%d: here you go." % ticket_id
        self.makeGitCommit(GIT, 'newfile', 'with some new content', message)
        self.openGitHubHook()

        ticket = Ticket(self.env, ticket_id)
        self.assertEqual(ticket['status'], 'closed')
        self.assertEqual(ticket['resolution'], 'fixed')
        changelog = ticket.get_changelog()
        self.assertEqual(len(changelog), 4)
        self.assertEqual(changelog[0][2], 'comment')
        self.assertIn("here you go", changelog[0][4])

    def testComplexNotification(self):
        ticket1 = Ticket(self.env)
        ticket1['summary'] = 'Fix please.'
        ticket1['status'] = 'new'
        ticket1_id = ticket1.insert()
        ticket2 = Ticket(self.env)
        ticket2['summary'] = 'This one too, thanks.'
        ticket2['status'] = 'new'
        ticket2_id = ticket2.insert()

        ticket1 = Ticket(self.env, ticket1_id)
        self.assertEqual(ticket1['status'], 'new')
        self.assertEqual(ticket1['resolution'], '')
        ticket2 = Ticket(self.env, ticket2_id)
        self.assertEqual(ticket2['status'], 'new')
        self.assertEqual(ticket2['resolution'], '')

        message1 = "Fix #%d: you're welcome." % ticket1_id
        self.makeGitCommit(ALTGIT, 'newfile', 'with some new content', message1)
        message2 = "See #%d: you bet." % ticket2_id
        self.makeGitCommit(ALTGIT, 'newfile', 'with improved content', message2)
        self.openGitHubHook(2, 'alt')

        ticket1 = Ticket(self.env, ticket1_id)
        self.assertEqual(ticket1['status'], 'closed')
        self.assertEqual(ticket1['resolution'], 'fixed')
        changelog1 = ticket1.get_changelog()
        self.assertEqual(len(changelog1), 4)
        self.assertEqual(changelog1[0][2], 'comment')
        self.assertIn("you're welcome", changelog1[0][4])
        ticket2 = Ticket(self.env, ticket2_id)
        self.assertEqual(ticket2['status'], 'new')
        self.assertEqual(ticket2['resolution'], '')
        changelog2 = ticket2.get_changelog()
        self.assertEqual(len(changelog2), 1)
        self.assertEqual(changelog2[0][2], 'comment')
        self.assertIn("you bet", changelog2[0][4])

    def testPing(self):
        payload = {'zen': "Readability counts."}
        headers = {'Content-Type': 'application/json', 'X-GitHub-Event': 'ping'}
        request = urllib2.Request(URL + 'github', json.dumps(payload), headers)
        output = urllib2.urlopen(request).read()
        self.assertEqual(output, "Readability counts.")

    def testUnknownEvent(self):
        headers = {'Content-Type': 'application/json', 'X-GitHub-Event': 'pull'}
        request = urllib2.Request(URL + 'github', json.dumps({}), headers)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 400: Bad Request$'):
            urllib2.urlopen(request)

    def testBadMethod(self):
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 405: Method Not Allowed$'):
            urllib2.urlopen(URL + 'github')

    def testBadPayload(self):
        request = urllib2.Request(URL + 'github', 'foobar', HEADERS)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 400: Bad Request$'):
            urllib2.urlopen(request)

    def testBadRepository(self):
        request = urllib2.Request(URL + 'github/nosuchrepo', '{}', HEADERS)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 400: Bad Request$'):
            urllib2.urlopen(request)

    def testBadUrl(self):
        request = urllib2.Request(URL + 'githubnosuchurl', '{}', HEADERS)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 404: Not Found$'):
            urllib2.urlopen(request)


class GitHubBrowserWithCacheTests(GitHubBrowserTests):

    cached_git = True


class GitHubPostCommitHookWithCacheTests(GitHubPostCommitHookTests):

    cached_git = True


if __name__ == '__main__':
    if glob.glob('test-*'):
        print "Test data remains from previous runs, aborting."
        print "Run `rm -rf test-*` and retry."
        sys.exit(1)
    if '--with-coverage' in sys.argv:
        COVERAGE = True
        sys.argv.remove('--with-coverage')
    if '--with-trac-log' in sys.argv:
        SHOW_LOG = True
        sys.argv.remove('--with-trac-log')
    unittest.main()

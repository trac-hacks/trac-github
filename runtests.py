#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This software is licensed as described in the file LICENSE, which
# you should have received as part of this distribution.

"""Functional tests for the Trac-GitHub plugin.

Trac's testing framework isn't well suited for plugins, so we NIH'd a bit.
"""

import argparse
import BaseHTTPServer
import ConfigParser
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
import urllib2
import urlparse

from lxml import html

from trac.env import Environment
from trac.ticket.model import Ticket
from trac.util.translation import _

import requests


GIT = 'test-git-foo'
ALTGIT = 'test-git-bar'
NOGHGIT = 'test-git-nogithub'
TESTDIR = '.'

ENV = 'test-trac-github'
CONF = '%s/conf/trac.ini' % ENV
HTDIGEST = '%s/passwd' % ENV
URL = 'http://localhost:8765/%s' % ENV
SECRET = 'test-secret'
HEADERS = {'Content-Type': 'application/json', 'X-GitHub-Event': 'push'}
UPDATEHOOK = '%s-mirror/hooks/trac-github-update' % GIT

# Global variables overriden when running the module (see very bottom of file)
COVERAGE = False
SHOW_LOG = False
TRAC_ADMIN_BIN = 'trac-admin'
TRACD_BIN = 'tracd'
COVERAGE_BIN = 'coverage'
GIT_DEFAULT_BRANCH = 'main'


class HttpNoRedirectHandler(urllib2.HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib2.HTTPError(req.get_full_url(), code, msg, headers, fp)

urllib2.install_opener(urllib2.build_opener(HttpNoRedirectHandler()))


def d(*args):
    """
    Return an absolute path where the given arguments are joined and
    prepended with the TESTDIR.
    """
    return os.path.join(TESTDIR, *args)


def git_check_output(*args, **kwargs):
    """
    Run the given git command (`*args`), optionally on the given
    repository (`kwargs['repo']`), return the output of that command
    as a string.
    """
    repo = kwargs.pop('repo', None)

    if repo is None:
        cmdargs = ["git"] + list(args)
    else:
        cmdargs = ["git", "-C", d(repo)] + list(args)

    return subprocess.check_output(cmdargs, **kwargs)


class TracGitHubTests(unittest.TestCase):

    cached_git = False

    @classmethod
    def setUpClass(cls):
        cls.createGitRepositories()
        cls.createTracEnvironment()
        cls.startTracd()
        cls.env = Environment(d(ENV))

    @classmethod
    def tearDownClass(cls):
        cls.env.shutdown()
        cls.stopTracd()
        cls.removeTracEnvironment()
        cls.removeGitRepositories()

    @classmethod
    def createGitRepositories(cls):
        git_check_output('init', d(GIT))
        git_check_output('init', d(ALTGIT))
        git_check_output('init', d(NOGHGIT))
        cls.makeGitCommit(GIT, 'README', 'default git repository\n')
        cls.makeGitCommit(ALTGIT, 'README', 'alternative git repository\n')
        cls.makeGitCommit(NOGHGIT, 'README', 'git repository not on GitHub\n')
        git_check_output('clone', '--quiet', '--mirror', d(GIT), d('%s-mirror' % GIT))
        git_check_output('clone', '--quiet', '--mirror', d(ALTGIT), d('%s-mirror' % ALTGIT))

    @classmethod
    def removeGitRepositories(cls):
        shutil.rmtree(d(GIT))
        shutil.rmtree(d(ALTGIT))
        shutil.rmtree(d(NOGHGIT))
        shutil.rmtree(d('%s-mirror' % GIT))
        shutil.rmtree(d('%s-mirror' % ALTGIT))

    @classmethod
    def createTracEnvironment(cls, **kwargs):
        subprocess.check_output([TRAC_ADMIN_BIN, d(ENV), 'initenv',
                'Trac - GitHub tests', 'sqlite:db/trac.db'])
        subprocess.check_output([TRAC_ADMIN_BIN, d(ENV), 'permission',
                'add', 'anonymous', 'TRAC_ADMIN'])

        conf = ConfigParser.ConfigParser()
        with open(d(CONF), 'rb') as fp:
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

        cached_git = cls.cached_git
        if 'cached_git' in kwargs:
            cached_git = kwargs['cached_git']
        if cached_git:
            conf.add_section('git')
            conf.set('git', 'cached_repository', 'true')
            conf.set('git', 'persistent_cache', 'true')

        if not conf.has_section('github'):
            conf.add_section('github')
        client_id = '01234567890123456789'
        if 'client_id' in kwargs:
            client_id = kwargs['client_id']
        conf.set('github', 'client_id', client_id)
        client_secret = '0123456789abcdef0123456789abcdef012345678'
        if 'client_secret' in kwargs:
            client_secret = kwargs['client_secret']
        conf.set('github', 'client_secret', client_secret)
        conf.set('github', 'repository', 'aaugustin/trac-github')
        conf.set('github', 'alt.repository', 'follower/trac-github')
        conf.set('github', 'alt.branches', '%s stable/*' % GIT_DEFAULT_BRANCH)
        if 'request_email' in kwargs:
            conf.set('github', 'request_email', kwargs['request_email'])
        if 'preferred_email_domain' in kwargs:
            conf.set('github', 'preferred_email_domain', kwargs['preferred_email_domain'])
        if 'organization' in kwargs:
            conf.set('github', 'organization', kwargs['organization'])
        if 'username' in kwargs and 'access_token' in kwargs:
            conf.set('github', 'username', kwargs['username'])
            conf.set('github', 'access_token', kwargs['access_token'])
        if 'webhook_secret' in kwargs:
            conf.set('github', 'webhook_secret', kwargs['webhook_secret'])
        if 'username_prefix' in kwargs:
            conf.set('github', 'username_prefix', kwargs['username_prefix'])

        if SHOW_LOG:
            # The [logging] section already exists in the default trac.ini file.
            conf.set('logging', 'log_type', 'stderr')
        else:
            # Write debug log so you can read it on crashes
            conf.set('logging', 'log_type', 'file')
            conf.set('logging', 'log_file', 'trac.log')
            conf.set('logging', 'log_level', 'DEBUG')

        conf.add_section('repositories')
        conf.set('repositories', '.dir', d('%s-mirror' % GIT))
        conf.set('repositories', '.type', 'git')
        conf.set('repositories', 'alt.dir', d('%s-mirror' % ALTGIT))
        conf.set('repositories', 'alt.type', 'git')
        conf.set('repositories', 'nogh.dir', d(NOGHGIT, '.git'))
        conf.set('repositories', 'nogh.type', 'git')

        # Show changed files in timeline, which will trigger the
        # IPermissionPolicy code paths
        conf.set('timeline', 'changeset_show_files', '-1')
        old_permission_policies = conf.get('trac', 'permission_policies')
        if 'GitHubPolicy' not in old_permission_policies:
            conf.set('trac', 'permission_policies',
                     'GitHubPolicy, %s' % old_permission_policies)

        with open(d(CONF), 'wb') as fp:
            conf.write(fp)

        with open(d(HTDIGEST), 'w') as fp:
            # user: user, pass: pass, realm: realm
            fp.write("user:realm:8493fbc53ba582fb4c044c456bdc40eb\n")

        run_resync = kwargs['resync'] if 'resync' in kwargs else True
        if run_resync:
            # Allow skipping resync for perfomance reasons if not required
            subprocess.check_output([TRAC_ADMIN_BIN, d(ENV), 'repository', 'resync', ''])
            subprocess.check_output([TRAC_ADMIN_BIN, d(ENV), 'repository', 'resync', 'alt'])
            subprocess.check_output([TRAC_ADMIN_BIN, d(ENV), 'repository', 'resync', 'nogh'])

    @classmethod
    def removeTracEnvironment(cls):
        shutil.rmtree(d(ENV))

    @classmethod
    def startTracd(cls, **kwargs):
        if COVERAGE:
            tracd = [COVERAGE_BIN, 'run', '--append', '--branch',
                     '--source=tracext.github', TRACD_BIN]

        else:
            tracd = [TRACD_BIN]
        if SHOW_LOG:
            kwargs['stdout'] = sys.stdout
            kwargs['stderr'] = sys.stderr
        cls.tracd = subprocess.Popen(tracd + ['--port', '8765', '--auth=*,%s,realm' % d(HTDIGEST), d(ENV)], **kwargs)

        waittime = 0.1
        for _ in range(5):
            try:
                urllib2.urlopen(URL)
            except urllib2.URLError:
                time.sleep(waittime)
                waittime *= 2
            else:
                break
        else:
            raise RuntimeError("Can't communicate with tracd running on port 8765")

    @classmethod
    def stopTracd(cls):
        cls.tracd.send_signal(signal.SIGINT)
        cls.tracd.wait()

    @staticmethod
    def makeGitBranch(repo, branch):
        git_check_output('branch', branch, repo=repo)

    @staticmethod
    def makeGitCommit(repo, path, content, message='edit', branch=None):
        if branch is None:
            branch = GIT_DEFAULT_BRANCH

        if branch != GIT_DEFAULT_BRANCH:
            git_check_output('checkout', branch, repo=repo)
        with open(d(repo, path), 'wb') as fp:
            fp.write(content)
        git_check_output('add', path, repo=repo)
        git_check_output('commit', '-m', message, repo=repo)
        if branch != GIT_DEFAULT_BRANCH:
            git_check_output('checkout', GIT_DEFAULT_BRANCH, repo=repo)
        changeset = git_check_output('rev-parse', 'HEAD', repo=repo)
        return changeset.strip()

    @staticmethod
    def makeGitHubHookPayload(n=1, reponame=''):
        # See https://developer.github.com/v3/activity/events/types/#pushevent
        # We don't reproduce the entire payload, only what the plugin needs.
        repo = {'': GIT, 'alt': ALTGIT}[reponame]

        commits = []
        log = git_check_output(
            'log',
            '-%d' % n,
            '--branches',
            '--format=oneline',
            '--topo-order',
            repo=repo
        )
        for line in log.splitlines():
            id, _, message = line.partition(' ')
            commits.append({'id': id, 'message': message, 'distinct': True})
        payload = {'commits': commits}
        return payload

    @staticmethod
    def openGitHubHook(n=1, reponame='', payload=None):
        if not payload:
            payload = TracGitHubTests.makeGitHubHookPayload(n, reponame)
        url = (URL + '/github/' + reponame) if reponame else URL + '/github'
        request = urllib2.Request(url, json.dumps(payload), HEADERS)
        return urllib2.urlopen(request)


class GitHubBrowserTests(TracGitHubTests):

    def testLinkToChangeset(self):
        self.makeGitCommit(GIT, 'myfile', 'for browser tests')
        changeset = self.openGitHubHook().read().rstrip()[-40:]
        try:
            urllib2.urlopen(URL + '/changeset/' + changeset)
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
            urllib2.urlopen(URL + '/changeset/' + changeset + '/alt')
        except urllib2.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            self.assertEqual(exc.headers['Location'],
                    'https://github.com/follower/trac-github/commit/%s' % changeset)
        else:
            self.fail("URL didn't redirect")

    def testNonGitHubLinkToChangeset(self):
        changeset = self.makeGitCommit(NOGHGIT, 'myfile', 'for browser tests')
        subprocess.check_output([TRAC_ADMIN_BIN, d(ENV), 'changeset', 'added', 'nogh', changeset])
        response = requests.get(URL + '/changeset/' + changeset + '/nogh', allow_redirects=False)
        self.assertEqual(response.status_code, 200)

    def testLinkToPath(self):
        self.makeGitCommit(GIT, 'myfile', 'for more browser tests')
        changeset = self.openGitHubHook().read().rstrip()[-40:]
        try:
            urllib2.urlopen(URL + '/changeset/' + changeset + '/myfile')
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
            urllib2.urlopen(URL + '/changeset/' + changeset + '/alt/myfile')
        except urllib2.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            self.assertEqual(exc.headers['Location'],
                    'https://github.com/follower/trac-github/blob/%s/myfile' % changeset)
        else:
            self.fail("URL didn't redirect")

    def testNonGitHubLinkToPath(self):
        changeset = self.makeGitCommit(NOGHGIT, 'myfile', 'for more browser tests')
        subprocess.check_output([TRAC_ADMIN_BIN, d(ENV), 'changeset', 'added', 'nogh', changeset])
        response = requests.get(URL + '/changeset/' + changeset + '/nogh/myfile', allow_redirects=False)
        self.assertEqual(response.status_code, 200)

    def testBadChangeset(self):
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 404: Not Found$'):
            urllib2.urlopen(URL + '/changeset/1234567890')

    def testBadUrl(self):
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 404: Not Found$'):
            urllib2.urlopen(URL + '/changesetnosuchurl')

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
        html = urllib2.urlopen(URL + '/timeline').read()
        self.assertTrue('msg 1' in html)
        self.assertTrue('msg 2' in html)
        self.assertTrue('msg 3' in html)
        self.assertTrue('msg 4' in html)
        self.assertTrue('msg 5' in html)
        self.assertFalse('msg 6' in html)


class GitHubLoginModuleTests(TracGitHubTests):

    @classmethod
    def startTracd(cls, **kwargs):
        # Disable check for HTTPS to avoid adding complexity to the test setup.
        kwargs['env'] = os.environ.copy()
        kwargs['env']['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        super(GitHubLoginModuleTests, cls).startTracd(**kwargs)

    def testLogin(self):
        response = requests.get(URL + '/github/login', allow_redirects=False)
        self.assertEqual(response.status_code, 302)

        redirect_url = urlparse.urlparse(response.headers['Location'])
        self.assertEqual(redirect_url.scheme, 'https')
        self.assertEqual(redirect_url.netloc, 'github.com')
        self.assertEqual(redirect_url.path, '/login/oauth/authorize')
        params = urlparse.parse_qs(redirect_url.query, keep_blank_values=True)
        state = params['state'][0]  # this is a random value
        self.assertEqual(params, {
            'client_id': ['01234567890123456789'],
            'redirect_uri': [URL + '/github/oauth'],
            'response_type': ['code'],
            'scope': [''],
            'state': [state],
        })

    def testOauthInvalidState(self):
        session = requests.Session()

        # This adds a oauth_state parameter in the Trac session.
        response = session.get(URL + '/github/login', allow_redirects=False)
        self.assertEqual(response.status_code, 302)

        response = session.get(
            URL + '/github/oauth?code=01234567890123456789&state=wrong_state',
            allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], URL)

        response = session.get(URL)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Invalid request. Please try to login again.", response.text)

    def testOauthInvalidStateWithoutSession(self):
        session = requests.Session()

        # There's no oauth_state parameter in the Trac session.
        # OAuth callback requests without state must still fail.

        response = session.get(
            URL + '/github/oauth?code=01234567890123456789',
            allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], URL)

        response = session.get(URL)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Invalid request. Please try to login again.", response.text)

    def testLogout(self):
        response = requests.get(URL + '/github/logout', allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], URL)

class GitHubLoginModuleConfigurationTests(TracGitHubTests):
    # Append custom failure messages to the automatically generated ones
    longMessage = True

    @classmethod
    def setUpClass(cls):
        cls.createGitRepositories()
        cls.mockdata = startAPIMock(8768)

        trac_env = os.environ.copy()
        trac_env.update({
            'TRAC_GITHUB_OAUTH_URL': 'http://127.0.0.1:8768/',
            'TRAC_GITHUB_API_URL': 'http://127.0.0.1:8768/',
            'OAUTHLIB_INSECURE_TRANSPORT': '1'
        })
        trac_env_broken = trac_env.copy()
        trac_env_broken.update({
            'TRAC_GITHUB_OAUTH_URL': 'http://127.0.0.1:8769/',
            'TRAC_GITHUB_API_URL': 'http://127.0.0.1:8769/',
        })
        trac_env_broken_api = trac_env.copy()
        trac_env_broken_api.update({
            'TRAC_GITHUB_API_URL': 'http://127.0.0.1:8769/',
        })

        cls.trac_env = trac_env
        cls.trac_env_broken = trac_env_broken
        cls.trac_env_broken_api = trac_env_broken_api

        with open(d(SECRET), 'wb') as fp:
            fp.write('98765432109876543210')


    @classmethod
    def tearDownClass(cls):
        cls.removeGitRepositories()
        os.remove(d(SECRET))

    def testLoginWithReqEmail(self):
        """Test that configuring request_email = true requests the user:email scope from GitHub"""
        with TracContext(self, request_email=True, resync=False):
            response = requests.get(URL + '/github/login', allow_redirects=False)
            self.assertEqual(response.status_code, 302)

            redirect_url = urlparse.urlparse(response.headers['Location'])
            self.assertEqual(redirect_url.scheme, 'https')
            self.assertEqual(redirect_url.netloc, 'github.com')
            self.assertEqual(redirect_url.path, '/login/oauth/authorize')
            params = urlparse.parse_qs(redirect_url.query, keep_blank_values=True)
            state = params['state'][0]  # this is a random value
            self.assertEqual(params, {
                'client_id': ['01234567890123456789'],
                'redirect_uri': [URL + '/github/oauth'],
                'response_type': ['code'],
                'scope': ['user:email'],
                'state': [state],
            })

    def loginAndVerifyClientId(self, expected_client_id):
        """
        Open the login page and check that the client_id in the redirect target
        matches the expected value.
        """
        response = requests.get(URL + '/github/login', allow_redirects=False)
        self.assertEqual(response.status_code, 302)

        redirect_url = urlparse.urlparse(response.headers['Location'])
        self.assertEqual(redirect_url.scheme, 'https')
        self.assertEqual(redirect_url.netloc, 'github.com')
        self.assertEqual(redirect_url.path, '/login/oauth/authorize')
        params = urlparse.parse_qs(redirect_url.query, keep_blank_values=True)
        state = params['state'][0]  # this is a random value
        self.assertEqual(params, {
            'client_id': [expected_client_id],
            'redirect_uri': [URL + '/github/oauth'],
            'response_type': ['code'],
            'scope': [''],
            'state': [state],
        })

    def testLoginWithSecretInEnvironment(self):
        """Test that passing client_id in environment works"""

        secret_env = os.environ.copy()
        secret_env.update({'TRAC_GITHUB_CLIENT_ID': '98765432109876543210'})

        with TracContext(self, client_id='TRAC_GITHUB_CLIENT_ID', env=secret_env):
            self.loginAndVerifyClientId('98765432109876543210')

    def testLoginWithSecretInFile(self):
        """Test that passing client_id in absolute path works"""

        path = d(SECRET)

        with TracContext(self, client_id=path):
            self.loginAndVerifyClientId('98765432109876543210')

    def testLoginWithSecretInRelativeFile(self):
        """Test that passing client_id in relative path works"""

        path = './' + os.path.relpath(d(SECRET))

        with TracContext(self, client_id=path):
            self.loginAndVerifyClientId('98765432109876543210')

    def testLoginWithUnconfiguredClientId(self):
        """Test that leaving client_id unconfigured prints a warning"""
        with TracContext(self, client_id=''):
            session = requests.Session()

            response = session.get(URL + '/github/login', allow_redirects=True)
            self.assertEqual(response.status_code, 200)

            tree = html.fromstring(response.content)
            errmsg = ''.join(tree.xpath('//div[@id="warning"]/text()')).strip()
            self.assertIn(
                "GitHubLogin configuration incomplete, missing client_id or "
                "client_secret", errmsg,
                "An unconfigured GitHubLogin module should redirect and print "
                "a warning on login attempts.")

    def attemptHttpAuth(self, testenv, **kwargs):
        """
        Helper method that attempts to log in using HTTP authentication in the
        given testenv; returns a tuple where the first item is the error
        message in the notification box on the trac page loaded after the login
        attempt (or an empty string on success) and the second item is the
        username as seen by trac.
        """
        with TracContext(self, env=testenv, resync=False, **kwargs):
            session = requests.Session()

            # This logs into trac using HTTP authentication
            # This adds a oauth_state parameter in the Trac session.
            response = session.get(URL + '/login', auth=requests.auth.HTTPDigestAuth('user', 'pass'))
            self.assertNotEqual(response.status_code, 403)

            response = session.get(URL + '/newticket') # this should trigger IPermissionGroupProvider
            self.assertEqual(response.status_code, 200)
            tree = html.fromstring(response.content)
            warning = ''.join(tree.xpath('//div[@id="warning"]/text()')).strip()
            user = ''
            match = re.match(r"logged in as (.*)",
                             ', '.join(tree.xpath('//div[@id="metanav"]/ul/li[@class="first"]/text()')))
            if match:
                user = match.group(1)
            return (warning, user)

    def attemptValidOauth(self, testenv, callback, **kwargs):
        """
        Helper method that runs a valid OAuth2 attempt in the given testenv
        with the given callback; returns a tuple where the first item is the
        error message in the notification box on the trac page loaded after the
        login attempt (or an empty string on success), the second item is
        a list of email addresses found in email fields of the preferences
        after login and the third item is the username of the user that was
        logged in as seen by trac..
        """
        ctxt_kwargs = {}
        other_kwargs = {}
        for kwarg in kwargs:
            if kwarg in TracContext._valid_attrs:
                ctxt_kwargs[kwarg] = kwargs[kwarg]
            else:
                other_kwargs[kwarg] = kwargs[kwarg]
        with TracContext(self, env=testenv, resync=False, **ctxt_kwargs):
            updateMockData(self.mockdata, postcallback=callback, **other_kwargs)
            try:
                session = requests.Session()

                # This adds a oauth_state parameter in the Trac session.
                response = session.get(URL + '/github/login', allow_redirects=False)
                self.assertEqual(response.status_code, 302)

                # Extract the state from the redirect
                redirect_url = urlparse.urlparse(response.headers['Location'])
                params = urlparse.parse_qs(redirect_url.query, keep_blank_values=True)
                state = params['state'][0]  # this is a random value
                response = session.get(
                    URL + '/github/oauth',
                    params={
                        'code': '01234567890123456789',
                        'state': state
                    },
                    allow_redirects=False)
                self.assertEqual(response.status_code, 302)

                response = session.get(URL + '/prefs')
                self.assertEqual(response.status_code, 200)
                tree = html.fromstring(response.content)
                warning = ''.join(tree.xpath('//div[@id="warning"]/text()')).strip()
                email = tree.xpath('//input[@id="email"]/@value')
                user = ''
                match = re.match(r"logged in as (.*)",
                                 ', '.join(tree.xpath('//div[@id="metanav"]/ul/li[@class="first"]/text()')))
                if match:
                    user = match.group(1)
                return (warning, email, user)
            finally:
                # disable callback again
                updateMockData(self.mockdata, postcallback="")

    def testOauthBackendUnavailable(self):
        """
        Test that an OAuth backend that resets the connection does not crash
        the login
        """
        errmsg, emails, _ = self.attemptValidOauth(self.trac_env_broken, "")
        self.assertIn(
            "Invalid request. Please try to login again.",
            errmsg,
            "OAuth Authorization Request with unavailable backend should not succeed.")

    def testOauthBackendFails(self):
        """Test that an OAuth backend that fails does not crash the login"""
        def cb(path, args):
            return 403, {}
        errmsg, emails, _ = self.attemptValidOauth(self.trac_env, cb)
        self.assertIn(
            "Invalid request. Please try to login again.",
            errmsg,
            "OAuth Authorization Request with failing backend should not succeed.")

    def oauthCallbackSuccess(self, path, args):
        """
        GitHubAPIMock POST callback that contains a successful OAuth
        Authentication Response
        """
        return 200, {
            'access_token': '190c20e9d87de41264749672ccacdd63a0ae2345a63b2703e26e651248c3b50e',
            'token_type': 'bearer'
        }

    def testOauthValidButUnavailAPI(self):
        """
        Test that accessing an unavailable GitHub API with what seems to be
        a valid OAuth2 token does not crash the login
        """
        errmsg, emails, _ = self.attemptValidOauth(self.trac_env_broken_api, self.oauthCallbackSuccess)
        self.assertIn(
            "An error occurred while communicating with the GitHub API",
            errmsg,
            "Request to unavailable API with valid OAuth token should print an error.")

    def testOauthValidButBrokenAPI(self):
        """
        Test that accessing an broken GitHub API with what seems to be a valid
        OAuth2 token does not crash the login
        """
        errmsg, emails, _ = self.attemptValidOauth(self.trac_env_broken_api,
                                                   self.oauthCallbackSuccess,
                                                   retcode=403)
        self.assertIn(
            "An error occurred while communicating with the GitHub API",
            errmsg,
            "Failing API request with valid OAuth token should print an error.")

    def testOauthValidEmailAPIInvalid(self):
        """
        Test that a login with a valid OAuth2 but invalid data returned from
        the email request API does not crash
        """
        answers = {
            '/user': {
                'user': 'trololol',
                'email': 'lololort@example.com',
                'login': 'trololol'
            },
            '/user/email': {
                'foo': 'bar'
            }
        }

        errmsg, emails, _ = self.attemptValidOauth(
                self.trac_env, self.oauthCallbackSuccess, retcode=200,
                answers=answers, request_email=True)
        self.assertIn(
            "An error occurred while retrieving your email address from the GitHub API",
            errmsg,
            "Failing email API request with valid OAuth token should print an error.")

    def getEmail(self, answers, **kwargs):
        """Get and return the email address the system has chosen for the given config and answers"""
        errmsg, emails, _ = self.attemptValidOauth(
                self.trac_env, self.oauthCallbackSuccess, retcode=200,
                answers=answers, **kwargs)
        self.assertEqual(len(errmsg), 0,
                         "Successful login should not print an error.")

        return emails

    def getUser(self, answers, **kwargs):
        """Get and return the user name the system has chosen for the given config and answers"""
        errmsg, _, user = self.attemptValidOauth(
                self.trac_env, self.oauthCallbackSuccess, retcode=200,
                answers=answers, **kwargs)
        self.assertEqual(len(errmsg), 0,
                         "Successful login should not print an error.")

        return user

    def testOauthValid(self):
        """Test that a login with a valid OAuth2 token succeeds"""
        answers = {
            '/user': {
                'user': 'trololol',
                'email': 'lololort@example.com',
                'login': 'trololol'
            }
        }

        email = self.getEmail(answers)
        self.assertEqual(email, ['lololort@example.com'])
        user = self.getUser(answers)
        self.assertEqual(user, 'trololol')

    def testUsernamePrefix(self):
        """Test that setting a prefix for GitHub usernames works"""
        answers = {
            '/user': {
                'user': 'trololol',
                'email': 'lololort@example.com',
                'login': 'trololol'
            }
        }

        user = self.getUser(answers, username_prefix='github-')
        self.assertEqual(user, 'github-trololol')

        errmsg, user = self.attemptHttpAuth(self.trac_env,
                                            username_prefix='github-',
                                            organization='org',
                                            username='github-bot-user',
                                            access_token='accesstoken')
        self.assertEqual(len(errmsg), 0,
                         "HTTP authentication should still work.")
        self.assertEqual(user, "user",
                         "Non-GitHub-authentication should yield unprefixed usernames")

    def testOauthEmailIgnoresUnverified(self):
        """
        Test that request_email=True ignores unverified email addresses and
        prefers primary addresses
        """
        answers = {
            '/user': {
                'user': 'trololol',
                'login': 'trololol'
            },
            '/user/emails': [
                {
                    'email': 'torvalds@linux-foundation.org',
                    'verified': False,
                    'primary': True
                },
                {
                    'email': 'lololort@example.net',
                    'verified': True,
                    'primary': False
                },
                {
                    'email': 'lololort@example.com',
                    'verified': True,
                    'primary': True
                },
            ]
        }

        email = self.getEmail(answers, request_email=True)
        self.assertEqual(email, ['lololort@example.com'])

    def testPreferredEmailDomain(self):
        """
        Test that an email address matching the preferred email domain is
        preferred to one marked primary.
        """
        answers = {
            '/user': {
                'user': 'trololol',
                'login': 'trololol'
            },
            '/user/emails': [
                {
                    'email': 'torvalds@linux-foundation.org',
                    'verified': False,
                    'primary': True
                },
                {
                    'email': 'lololort@example.com',
                    'verified': True,
                    'primary': True
                },
                {
                    'email': 'lololort@example.net',
                    'verified': True,
                    'primary': False
                },
            ]
        }

        email = self.getEmail(answers, request_email=True,
                              preferred_email_domain='example.net')
        self.assertEqual(email, ['lololort@example.net'])

    def testPreferredEmailFallbackToPrimary(self):
        """
        Test that the primary address is chosen if no address matches the
        preferred email domain.
        """
        answers = {
            '/user': {
                'user': 'trololol',
                'login': 'trololol'
            },
            '/user/emails': [
                {
                    'email': 'lololort@example.com',
                    'verified': True,
                    'primary': True
                },
                {
                    'email': 'lololort@example.net',
                    'verified': True,
                    'primary': False
                },
            ]
        }

        email = self.getEmail(answers, request_email=True,
                              preferred_email_domain='example.org')
        self.assertEqual(email, ['lololort@example.com'])

    def testPreferredEmailCaseInsensitive(self):
        """
        Test that the preferred email domain is honoured regardless of case.
        """
        answers = {
            '/user': {
                'user': 'trololol',
                'login': 'trololol'
            },
            '/user/emails': [
                {
                    'email': 'lololort@example.com',
                    'verified': True,
                    'primary': True
                },
                {
                    'email': 'lololort@EXAMPLE.NET',
                    'verified': True,
                    'primary': False
                },
            ]
        }

        email = self.getEmail(answers, request_email=True,
                              preferred_email_domain='example.net')
        self.assertEqual(email, ['lololort@EXAMPLE.NET'])


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
        request = urllib2.Request(URL + '/github', json.dumps(payload), HEADERS)
        output = urllib2.urlopen(request).read()
        self.assertRegexpMatches(output, r"Running hook on \(default\)\n"
                                         r"\* Updating clone\n"
                                         r"\* Synchronizing with clone\n"
                                         r"\* Unknown commit [0-9a-f]{40}\n")

    def testNotification(self):
        ticket = Ticket(self.env)
        ticket['summary'] = 'I need a commit!'
        ticket['status'] = 'new'
        ticket['owner'] = ''
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
        # Trac 1.2 generates three fields, Trac 1.0 four.
        self.assertGreaterEqual(len(changelog1), 3)
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
        request = urllib2.Request(URL + '/github', json.dumps(payload), headers)
        output = urllib2.urlopen(request).read()
        self.assertEqual(output, "Readability counts.")

    def testUnknownEvent(self):
        headers = {'Content-Type': 'application/json', 'X-GitHub-Event': 'pull'}
        request = urllib2.Request(URL + '/github', json.dumps({}), headers)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 400: Bad Request$'):
            urllib2.urlopen(request)

    def testBadMethod(self):
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 405: Method Not Allowed$'):
            urllib2.urlopen(URL + '/github')

    def testBadPayload(self):
        request = urllib2.Request(URL + '/github', 'foobar', HEADERS)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 400: Bad Request$'):
            urllib2.urlopen(request)

    def testBadRepository(self):
        request = urllib2.Request(URL + '/github/nosuchrepo', '{}', HEADERS)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 400: Bad Request$'):
            urllib2.urlopen(request)

    def testBadUrl(self):
        request = urllib2.Request(URL + '/githubnosuchurl', '{}', HEADERS)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 404: Not Found$'):
            urllib2.urlopen(request)


class GitHubPostCommitHookWithSignedWebHookTests(TracGitHubTests):

    @classmethod
    def setUpClass(cls):
        cls.createGitRepositories()
        cls.createTracEnvironment(webhook_secret='6c12713595df9247974fa0f2f99b94c815f242035c49c7f009892bfd7d9f0f98')
        cls.startTracd()
        cls.env = Environment(d(ENV))

    def testUnsignedPing(self):
        payload = {'zen': "Readability counts."}
        headers = {'Content-Type': 'application/json', 'X-GitHub-Event': 'ping'}
        request = urllib2.Request(URL + '/github', json.dumps(payload), headers)
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 403: Forbidden$'):
            urllib2.urlopen(request).read()

    def testSignedPing(self):
        # Correct signature can be generated with OpenSSL:
        #  $> printf '{"zen": "Echo me"}\n' | openssl dgst -sha256 -hmac $webhook_secret
        payload = {'zen': "Echo me"}
        signature = "sha256=cacc93c2df1b21313e16d8690fc21e56229b6a9525e7016db38bdf9bad708fed"
        headers = {'Content-Type': 'application/json',
                   'X-GitHub-Event': 'ping',
                   'X-Hub-Signature': signature}
        request = urllib2.Request(URL + '/github', json.dumps(payload) + '\n', headers)
        output = urllib2.urlopen(request).read()
        self.assertEqual(output, "Echo me")


class GitHubPostCommitHookWithUpdateHookTests(TracGitHubTests):

    @classmethod
    def createUpdateHook(cls):
        with open(d(UPDATEHOOK), 'wb') as fp:
            # simple shell script to echo back all input
            fp.write("""#!/bin/sh\nexec cat""")
            os.fchmod(fp.fileno(), 0o755)

    def createFailingUpdateHook(cls):
        with open(d(UPDATEHOOK), 'wb') as fp:
            fp.write("""#!/bin/sh\nexit 1""")
            os.fchmod(fp.fileno(), 0o755)

    @classmethod
    def removeUpdateHook(cls):
        os.remove(d(UPDATEHOOK))

    @classmethod
    def setUpClass(cls):
        super(GitHubPostCommitHookWithUpdateHookTests, cls).setUpClass()
        # Make sure the hooks directory exists in the repo (can be disabled in some git configs)
        try:
            os.mkdir(d('%s-mirror' % GIT, 'hooks'))
        except OSError:
            pass
        cls.createUpdateHook()

    @classmethod
    def tearDownClass(cls):
        cls.removeUpdateHook()
        super(GitHubPostCommitHookWithUpdateHookTests, cls).tearDownClass()

    def testUpdateHook(self):
        self.makeGitCommit(GIT, 'foo', 'foo content\n')
        payload = self.makeGitHubHookPayload()
        output = self.openGitHubHook(payload=payload).read()
        self.assertRegexpMatches(output, r"Running hook on \(default\)\n"
                                         r"\* Updating clone\n"
                                         r"\* Synchronizing with clone\n"
                                         r"\* Adding commit [0-9a-f]{40}\n"
                                         r"\* Running trac-github-update hook\n")
        self.assertEqual(output.split('\n')[-1], json.dumps(payload))

    def testUpdateHookExecFailure(self):
        os.chmod(d(UPDATEHOOK), 0o644)
        self.makeGitCommit(GIT, 'bar', 'bar content\n')
        payload = self.makeGitHubHookPayload()
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 500: Internal Server Error$'):
            output = self.openGitHubHook(payload=payload).read()

    def testUpdateHookFailure(self):
        self.createFailingUpdateHook()
        self.makeGitCommit(GIT, 'baz', 'baz content\n')
        payload = self.makeGitHubHookPayload()
        with self.assertRaisesRegexp(urllib2.HTTPError, r'^HTTP Error 500: Internal Server Error$'):
            output = self.openGitHubHook(payload=payload).read()


class GitHubBrowserWithCacheTests(GitHubBrowserTests):

    cached_git = True


class GitHubPostCommitHookWithCacheTests(GitHubPostCommitHookTests):

    cached_git = True


class GitHubAPIMock(BaseHTTPServer.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Visibly differentiate GitHub API mock logging from tracd logs
        sys.stderr.write("%s [%s] %s\n" %
                         (self.__class__.__name__,
                          self.log_date_time_string(),
                          format%args))

    def do_GET(self):
        md = self.server.mockdata
        md['lock'].acquire()
        retcode = md['retcode']
        contenttype = md['content-type']
        answers = md['answers'].copy()
        md['lock'].release()

        path, _, querystring = self.path.partition('?')
        parameters = {k: v for k, _, v in (q.partition('=') for q in querystring.split('&') if q)}

        if path in answers:
            answer = answers[path]
        else:
            answer = {'message': 'No handler for URI %s' % path}
            retcode = 404

        self.send_response(retcode)

        # Add pagination
        per_page = 5
        if isinstance(answer, list):
            length = len(answer)
            page = int(parameters.get('page', 1))
            start = (page - 1) * per_page
            end = page * per_page
            answer = answer[start:end]

            links = []
            if page > 1:
                prevparams = parameters.copy()
                prevparams.update({'page': (page - 1)})
                prev_link = '<http://{}{}?{}>; rel="prev"'.format(
                    self.headers['Host'],
                    path,
                    '&'.join(('='.join((str(k), str(v))) for k, v in prevparams.iteritems()))
                )
                links.append(prev_link)
            if length >= end:
                nextparams = parameters.copy()
                nextparams.update({'page': (page + 1)})
                next_link = '<http://{}{}?{}>; rel="next"'.format(
                    self.headers['Host'],
                    path,
                    '&'.join(('='.join((str(k), str(v))) for k, v in nextparams.iteritems()))
                )
                links.append(next_link)
            if len(links) > 0:
                self.send_header("Link", ", ".join(links))

        self.send_header("Content-Type", contenttype)
        self.end_headers()

        self.wfile.write(json.dumps(answer))

    def do_POST(self):
        md = self.server.mockdata
        md['lock'].acquire()
        retcode = md['retcode']
        contenttype = md['content-type']
        postcallback = md['post-callback']
        md['lock'].release()

        max_chunk_size = 10*1024*1024
        size_remaining = int(self.headers["content-length"])
        L = []
        while size_remaining:
            chunk_size = min(size_remaining, max_chunk_size)
            chunk = self.rfile.read(chunk_size)
            if not chunk:
                break
            L.append(chunk)
            size_remaining -= len(L[-1])
        args = urlparse.parse_qs(''.join(L))

        retcode = 404
        answer = {}
        if postcallback:
            try:
                retcode, answer = postcallback(self.path, args)
            except Exception:
                retcode = 500
                answer = traceback.format_exc()

        self.send_response(retcode)
        self.send_header("Content-Type", contenttype)
        self.end_headers()
        self.wfile.write(json.dumps(answer))


class TracContext(object):
    """
    Context manager that starts and stops a configured tracd instance on port
    8765.
    """

    _valid_attrs = ('cached_git',
                    'client_id',
                    'client_secret',
                    'request_email',
                    'preferred_email_domain',
                    'organization',
                    'username',
                    'access_token',
                    'webhook_secret',
                    'username_prefix',
                    'resync')
    """ List of all valid attributes to be passed to createTracEnvironment() """

    cached_git = False
    """ Whether to use a persistent repository cache """

    traclock = threading.Lock()
    """ Lock to ensure no two trac instances are started simultaneously. """

    def __init__(self, testobj, env=None, **kwargs):
        """
        Set up a new Trac context manager. Arguments are:

        :param testobj: An instance of `TracGitHubTests` used to create the
                        Trac environment and start tracd.
        :param env: Dictionary of environment variables to set when starting
                    tracd, or `None` for a copy of the current environment.
        :param client_id: Client ID for the GitHub OAuth application
        :param client_secret: Client Secret for the GitHub OAuth application
        :param request_email: `True` to request access to all email addresses
                              from GitHub in the login module; defaults to
                              `False`.
        :param cached_git: `True` to use a persistent repository cache;
                            defaults to `False`.
        :param organization: Name of the GitHub organization to configure for
                             group syncing. Defaults to unset.
        :param username: Username of the GitHub user to use for group syncing.
                         Defaults to unset.
        :param access_token: GitHub access token of the GitHub user to use for
                             group syncing. Defaults to unset.
        :param webhook_secret: Secret used to validate WebHook API calls if
                               present. Defaults to unset.
        :param username_prefix: Prefix for GitHub usernames to allow
                                co-existance of non-GitHub with GitHub accounts.
        :param resync: `False` to skip running `trac admin repository resync`
                       during environment setup for speed reasons. Defaults to
                       `True`.
        """
        for kwarg in kwargs:
            if kwarg in self._valid_attrs:
                setattr(self, kwarg, kwargs[kwarg])
        self._env = env
        self._testobj = testobj

    def __enter__(self):
        """
        Create a trac environment and start a tracd instance with this
        environment. Returns an instance of a `trac.env.Environment`.
        """
        # Only one trac environment at the same time because of the shared port
        # and FS resources
        self.traclock.acquire()

        # Set up trac env
        kwargs = {}
        for attr in self._valid_attrs:
            if hasattr(self, attr):
                kwargs[attr] = getattr(self, attr)
        self._testobj.createTracEnvironment(**kwargs)
        self._tracenv = Environment(d(ENV))

        # Start tracd
        self._testobj.startTracd(env=self._env)

        return self._tracenv

    def __exit__(self, etype, evalue, traceback):
        """
        Shut down a running tracd instance and clean up the environment. Always
        returns `False` to re-throw any exceptions that might have occurred.
        """
        # Stop tracd
        self._testobj.stopTracd()
        # Clean up trac env
        self._tracenv.shutdown()
        self._testobj.removeTracEnvironment()
        self.traclock.release()
        return False

class GitHubGroupsProviderTests(TracGitHubTests):
    # Append custom failure messages to the automatically generated ones
    longMessage = True
    # GitHubGroupsProvider configuration values (note that not all of those are always used!)
    organization = 'org'
    username = 'github-test-sync-user'
    access_token = 'e42b79d0a8275cab1f8c8c8ff0e2d99537b54ed9'
    webhook_secret = '6c12713595df9247974fa0f2f99b94c815f242035c49c7f009892bfd7d9f0f98'

    @classmethod
    def setUpClass(cls):
        cls.createGitRepositories()
        cls.mockdata = startAPIMock(8766)

        # Prepare sets of tracd environment variables
        tracd_env = os.environ.copy()
        tracd_env.update({'TRAC_GITHUB_API_URL': 'http://127.0.0.1:8766/'})
        tracd_env_debug = tracd_env.copy()
        tracd_env_debug.update({'TRAC_GITHUB_ENABLE_DEBUGGING': '1'})
        tracd_env_broken = tracd_env_debug.copy()
        tracd_env_broken.update({'TRAC_GITHUB_API_URL': 'http://127.0.0.1:8767/'})

        cls.tracd_env = tracd_env
        cls.tracd_env_debug = tracd_env_debug
        cls.tracd_env_broken = tracd_env_broken

        # Prepare sets of trac configuration settings
        trac_env = {
            'cached_git': True,
            'resync': False,
            'organization': cls.organization,
            'username': cls.username,
            'access_token': cls.access_token
        }
        trac_env_secured = trac_env.copy()
        trac_env_secured.update({
            'webhook_secret': cls.webhook_secret
        })

        cls.trac_env = trac_env
        cls.trac_env_secured = trac_env_secured

    @classmethod
    def tearDownClass(cls):
        cls.removeGitRepositories()
        # API Mock server is a daemon thread and will automatically stop

    def test_000_api_refuses_connection(self):
        """
        Test that a request does not fail even if the API refuses connections.
        """
        with TracContext(self, env=self.tracd_env_broken, **self.trac_env):
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200,
                             "Request with unresponsive API endpoint should not fail")
            self.assertEqual(response.json(), {},
                             "Unavailable API should yield no groups at all.")

    def test_001_unconfigured(self):
        """
        Test whether a request with an unconfigured GitHubGroupsProvider fails.
        """
        with TracContext(self, resync=False):
            response = requests.get(URL + '/newticket', allow_redirects=False)
            self.assertEqual(response.status_code, 200,
                             "Unconfigured GitHubGroupsProvider caused requests to fail")

    def test_002_disabled_debugging(self):
        """
        Test that the debugging functionality does not work if not explicitly enabled.
        """
        self.assertNotIn('TRAC_GITHUB_ENABLE_DEBUGGING', self.tracd_env,
                         "tracd_env enables debugging, but should not; did you export TRAC_GITHUB_ENABLE_DEBUGGING?")
        with TracContext(self, env=self.tracd_env, resync=False):
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 404,
                             "Debugging API was not enabled, but did not return HTTP 404")

    def test_003_api_returns_500(self):
        """
        Test that a request with a failing API endpoint still succeeds.
        """
        updateMockData(self.mockdata, retcode=500, answers={
            '/orgs/%s/teams' % self.organization: {}
        })
        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200,
                             "Request with failing API endpoint should not fail")
            self.assertEqual(response.json(), {},
                             "500 on API should yield no groups at all")

    def test_004_api_returns_404(self):
        """
        Test that a request with non-existant API endpoint still succeeds.
        """
        updateMockData(self.mockdata, retcode=404, answers={})

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200,
                             "Request with 404 API endpoint should not fail")
            self.assertEqual(response.json(), {},
                             "404 on API should yield no groups at all")

    def test_005_org_has_no_teams(self):
        """
        Test that a GitHub organization without teams is handled correctly.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200,
                             "Request with organization without teams should not fail")
            self.assertEqual(response.json(), {},
                             "No github teams should yield no groups, but groups were returned")

    def test_006_normal_operation(self):
        """
        Test results of normal operation and conversion of API results.
        """
        users = [
            {"login": u"octocat"},
            {"login": u"octobird"},
            {"login": u"octodolphin"},
            {"login": u"octofox"},
            {"login": u"octoraccoon"},
            {"login": u"octokangaroo"},
            {"login": u"octokoala"},
            {"login": u"octospider"}
        ]
        team1members = [
            users[0],
            users[1],
            users[2],
            users[4],
            users[5],
            users[6],
            users[7]
        ]
        team12members = [
            users[0],
            users[2],
            users[3]
        ]

        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: [
                {
                    "id": 1,
                    "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                    "name": u"Justice League",
                    "slug": u"justice-league"
                },
                {
                    "id": 12,
                    "url": u"%sorganizations/14143/team/12" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                    "name": u"The League of Extraordinary Gentlemen and Gentlewomen",
                    "slug": u"gentlepeople"
                }
            ],
            '/organizations/14143/team/1/members': team1members,
            '/organizations/14143/team/12/members': team12members
        })

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            # All users present?
            for user in users:
                login = user['login']
                self.assertIn(login, data, "user %s expected in groups" % login)
            # All users part of the org?
            for user in users:
                login = user['login']
                groups = data[login]
                self.assertIn(u"github-%s" % self.organization,
                              groups,
                              "user %s expected to be in organization group" % login)
                # and in the group exactly once?
                occurrences = len([x for x in groups if x == u"github-%s" % self.organization])
                self.assertEqual(occurrences, 1,
                                 "user %s is expected once in organization group" % login)

            # Users are in the groups where we expect them?
            for user in users:
                login = user['login']
                groups = data[login]
                if user in team1members:
                    self.assertIn(u"github-%s-justice-league" % self.organization,
                                  groups,
                                  "user %s expected in justice-league group" % login)
                else:
                    self.assertNotIn(u"github-%s-justice-league" % self.organization,
                                     groups,
                                     "user %s not expected in justice-league group" % login)
                if user in team12members:
                    self.assertIn(u"github-%s-gentlepeople" % self.organization,
                                  groups,
                                  "user %s expected in gentlepeople group" % login)
                else:
                    self.assertNotIn(u"github-%s-gentlepeople" % self.organization,
                                     groups,
                                     "user %s not expected in gentlepeople group" % login)

            # Any unexpected groups?
            allgroups = (u"github-%s" % self.organization,
                         u"github-%s-gentlepeople" % self.organization,
                         u"github-%s-justice-league" % self.organization)
            for user in users:
                login = user['login']
                for group in data[login]:
                    self.assertIn(group, allgroups,
                                  "Unexpected group found for user %s" % login)

            # Any unexpected users?
            allusers = [x["login"] for x in users]
            for login in data.keys():
                self.assertIn(login, allusers, "Unexpected user found in result")

    def test_007_hook_get_request(self):
        """
        Test that a GET request to /github-groups/? prints a message and returns HTTP 405.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env):
            response = requests.get(URL + '/github-groups', allow_redirects=False)
            self.assertEqual(response.status_code, 405,
                             "GET /github-groups did not return HTTP 405")
            self.assertEqual(response.text,
                             "Endpoint is ready to accept GitHub Organization membership notifications.\n")
            response = requests.get(URL + '/github-groups/', allow_redirects=False)
            self.assertEqual(response.status_code, 405,
                             "/github-groups/ did not return 405")
            self.assertEqual(response.text,
                             "Endpoint is ready to accept GitHub Organization membership notifications.\n")

    def test_008_hook_unsupported_event(self):
        """
        Test that unsupported events sent to /github-groups/ are handled correctly.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env):
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'FooEvent'})
            self.assertEqual(response.status_code, 400,
                             "Sending an unsupported event should return HTTP 400")
            self.assertEqual(response.text, "Event type FooEvent is not supported\n")

    def test_009_hook_ping_event(self):
        """
        Test that a ping event sent to /github-groups/ is handled correctly.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env):
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'ping'},
                                     json={'zen': 'Echo me!'})
            self.assertEqual(response.status_code, 200,
                             "Ping event should return HTTP 200")
            self.assertEqual(response.text, "Echo me!")

    def test_010_hook_ping_event_nonjson_payload(self):
        """
        Test that a ping event with non-JSON payload sent to /github-groups/ does not crash the service.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env):
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'ping'},
                                     data="Fail to parse as JSON")
            self.assertEqual(response.status_code, 400,
                             "Invalid payloads should return HTTP 400")
            self.assertEqual(response.text, "Invalid payload\n")

    def test_011_hook_ping_event_invalid_json_payload(self):
        """
        Test that a ping event without the expected JSON fields sent to /github-groups/ does not crash the service.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env):
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'ping'},
                                     json=[{'bar': 'baz'}])
            self.assertEqual(response.status_code, 500,
                             "Invalid payloads should return HTTP 500")
            self.assertIn("Exception occurred while handling payload, possible invalid payload\n", response.text)
            self.assertIn("Traceback (most recent call last):", response.text)

    def test_012_hook_membership_event_delete_team(self):
        """
        Test that deleting a team with an event sent to /github-groups/ works.
        """
        users = [
            {"login": u"octocat"},
            {"login": u"octobird"},
            {"login": u"octodolphin"},
            {"login": u"octofox"}
        ]
        team1members = [
            users[0],
            users[1],
            users[2]
        ]
        team12members = [
            users[0],
            users[2],
            users[3]
        ]

        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: [
                {
                    "id": 1,
                    "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                    "name": u"Justice League",
                    "slug": u"justice-league"
                },
                {
                    "id": 12,
                    "url": u"%sorganizations/14143/team/12" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                    "name": u"The League of Extraordinary Gentlemen and Gentlewomen",
                    "slug": u"gentlepeople"
                }
            ],
            '/organizations/14143/team/1/members': team1members,
            '/organizations/14143/team/12/members': team12members
        })

        update = {
            "team": {
                "id": 1,
                "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                "name": u"Justice League",
                "deleted": True
            }
        }

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            # Make sure the to-be-removed group exists
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            allgroups = set()
            for groups in data.values():
                allgroups.update(groups)
            self.assertIn(u"github-%s-justice-league" % self.organization, allgroups,
                          "Group to be removed not found in group output, test will be meaningless.")

            # Change the Mock API output
            updateMockData(self.mockdata, answers={
                '/orgs/%s/teams' % self.organization: [
                    {
                        "id": 12,
                        "url": u"%sorganizations/14143/team/12" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                        "name": u"The League of Extraordinary Gentlemen and Gentlewomen",
                        "slug": u"gentlepeople"
                    }
                ],
                '/organizations/14143/team/12/members': team12members
            })

            # Send the delete event
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'membership'},
                                     json=update)
            self.assertEqual(response.status_code, 200,
                             "MembershipEvent handling should return HTTP 200")
            self.assertEqual(response.text, "success")

            # Check that the group is gone
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertGreater(len(data), 0, "No groups returned after update")
            for login in data:
                groups = data[login]
                self.assertNotIn(u"github-%s-justice-league" % self.organization,
                                 groups,
                                 "Deleted group still shows up for user %s" % login)
            self.assertNotIn(users[1]["login"], data,
                             "user %s should have been removed completely, but is still present" % users[1]["login"])

    def test_013_hook_membership_event_delete_nonexistant_team(self):
        """
        Test that a membership event that deletes a non-existant team does not crash anything.
        """

        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        update = {
            "team": {
                "id": 1,
                "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                "name": u"Justice League",
                "deleted": True
            }
        }

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            # Send the delete event
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'membership'},
                                     json=update)
            self.assertEqual(response.status_code, 200,
                             "Deleting non-existant teams should return HTTP 200")
            self.assertEqual(response.text, "success")

    def test_014_hook_membership_event_add_team(self):
        """
        Test that adding a team with a MembershipEvent works as expected.
        """

        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        update = {
            "team": {
                "id": 1,
                "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                "name": u"Justice League",
                "slug": u"justice-league"
            }
        }

        users = [
            {"login": u"octocat"},
        ]
        team1members = [users[0]]

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            # Update the API result
            updateMockData(self.mockdata, retcode=200, answers={
                '/orgs/%s/teams' % self.organization: [
                    {
                        "id": 1,
                        "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                        "name": u"Justice League",
                        "slug": u"justice-league"
                    },
                ],
                '/organizations/14143/team/1/members': team1members,
            })

            # Send the update event
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'membership'},
                                     json=update)
            self.assertEqual(response.status_code, 200,
                             "Adding members to non-existant teams should return HTTP 200")
            self.assertEqual(response.text, "success")

            # Check that the member and group were added
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertGreater(len(data), 0, "No groups returned after update")
            self.assertIn(users[0]["login"], data,
                          "User %s expected after update, but not present" % users[0]["login"])
            self.assertItemsEqual(
                data[users[0]["login"]],
                (u"github-%s-justice-league" % self.organization, u"github-%s" % self.organization),
                "User %s does not have expected groups after update" % users[0]["login"])

    def test_015_hook_membership_event_add_member(self):
        """
        Test that adding a user to an existing team with a MembershipEvent works.
        """
        users = [
            {"login": u"octocat"},
            {"login": u"octofox"},
        ]
        team1members = [users[0]]

        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: [
                {
                    "id": 1,
                    "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                    "name": u"Justice League",
                    "slug": u"justice-league"
                },
            ],
            '/organizations/14143/team/1/members': list(team1members)
        })

        update = {
            "team": {
                "id": 1,
                "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                "name": u"Justice League",
                "slug": u"justice-league"
            }
        }

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            # Update the API result
            team1members.append(users[1])
            updateMockData(self.mockdata, retcode=200, answers={
                '/orgs/%s/teams' % self.organization: [
                    {
                        "id": 1,
                        "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                        "name": u"Justice League",
                        "slug": u"justice-league"
                    },
                ],
                '/organizations/14143/team/1/members': list(team1members)
            })

            # Send the update event
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'membership'},
                                     json=update)
            self.assertEqual(response.status_code, 200,
                             "Adding members to existing teams should return HTTP 200")
            self.assertEqual(response.text, "success")

            # Check that the member and group were added
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertGreater(len(data), 0, "No groups returned after update")
            self.assertIn(users[1]["login"], data,
                          "User %s expected after update, but not present" % users[1]["login"])
            self.assertItemsEqual(
                data[users[1]["login"]],
                (u"github-%s-justice-league" % self.organization, u"github-%s" % self.organization),
                "User %s does not have expected groups after update" % users[1]["login"])

    def test_016_hook_membership_event_remove_member(self):
        """
        Test that removing a member from an existing team using a MembershipEvent works.
        """
        users = [
            {"login": u"octocat"},
            {"login": u"octofox"},
        ]
        team1members = [users[0], users[1]]

        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: [
                {
                    "id": 1,
                    "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                    "name": u"Justice League",
                    "slug": u"justice-league"
                },
            ],
            '/organizations/14143/team/1/members': list(team1members)
        })

        update = {
            "team": {
                "id": 1,
                "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                "name": u"Justice League",
                "slug": u"justice-league"
            }
        }

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            # Update the API result
            team1members.remove(users[1])
            updateMockData(self.mockdata, retcode=200, answers={
                '/orgs/%s/teams' % self.organization: [
                    {
                        "id": 1,
                        "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                        "name": u"Justice League",
                        "slug": u"justice-league"
                    },
                ],
                '/organizations/14143/team/1/members': list(team1members)
            })

            # Send the update event
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'membership'},
                                     json=update)
            self.assertEqual(response.status_code, 200,
                             "Removing members from existing teams should return HTTP 200")
            self.assertEqual(response.text, "success")

            # Check that the member and group were added
            response = requests.get(URL + '/github-groups-dump', allow_redirects=False)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertGreater(len(data), 0, "No groups returned after update")
            self.assertNotIn(users[1]["login"], data,
                             "User %s not expected after update, but present" % users[1]["login"])

    def test_017_hook_unsigned_ping_event(self):
        """
        Test that an unsigned event sent to /github-groups/ is rejected if a webhook secret was configured.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env_secured):
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'ping'},
                                     json={'zen': 'Echo me!'})
            self.assertEqual(response.status_code, 403,
                             "Unsigned ping event should return HTTP 403")
            self.assertEqual(response.text, "Webhook signature verification failed\n")

    def test_018_hook_unsupported_sig_algo_ping_event(self):
        """
        Test that an event sent to /github-groups/ with an unsupported signature algorithm is rejected if a webhook secret was configured.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env_secured):
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={
                                         'X-GitHub-Event': 'ping',
                                         'X-Hub-Signature': 'foofoo=barbar'
                                     },
                                     json={'zen': 'Echo me!'})
            self.assertEqual(response.status_code, 403,
                             "Ping event with invalid signature algorithm should return HTTP 403")
            self.assertEqual(response.text, "Webhook signature verification failed\n")

    def test_019_hook_invalid_sig_ping_event(self):
        """
        Test that an event sent to /github-groups/ with an invalid signature is rejected if a webhook secret was configured.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env_secured):
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={
                                         'X-GitHub-Event': 'ping',
                                         'X-Hub-Signature': 'sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec15'
                                     },
                                     json={'zen': 'Echo me!'})
            self.assertEqual(response.status_code, 403,
                             "Ping event with invalid signature should return HTTP 403")
            self.assertEqual(response.text, "Webhook signature verification failed\n")

    def test_020_hook_signed_ping_event(self):
        """
        Test that a correctly signed ping event sent to /github-groups/ is accepted if a webhook secret was configured.
        """
        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        with TracContext(self, env=self.tracd_env, **self.trac_env_secured):
            # Correct signature can be generated with OpenSSL:
            #  $> printf '{"zen": "Echo me"}\n' | openssl dgst -sha256 -hmac $webhook_secret
            signature = "sha256=cacc93c2df1b21313e16d8690fc21e56229b6a9525e7016db38bdf9bad708fed"
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={
                                         'X-GitHub-Event': 'ping',
                                         'X-Hub-Signature': signature
                                     },
                                     data='{"zen": "Echo me"}\n')
            self.assertEqual(response.status_code, 200,
                             "Ping event with valid signature should return HTTP 200")
            self.assertEqual(response.text, "Echo me")

    def test_021_hook_membership_event_api_failure(self):
        """
        Test that a failing API after a membership event was sent correctly returns a failure state.
        """

        updateMockData(self.mockdata, retcode=200, answers={
            '/orgs/%s/teams' % self.organization: []
        })

        update = {
            "team": {
                "id": 1,
                "url": u"%sorganizations/14143/team/1" % self.tracd_env_debug.get('TRAC_GITHUB_API_URL'),
                "name": u"Justice League",
                "deleted": True
            }
        }

        with TracContext(self, env=self.tracd_env_debug, **self.trac_env):
            # Change the mock to always fail
            updateMockData(self.mockdata, retcode=403)
            # Send the delete event
            response = requests.post(URL + '/github-groups',
                                     allow_redirects=False,
                                     headers={'X-GitHub-Event': 'membership'},
                                     json=update)
            self.assertEqual(response.status_code, 500,
                             "Sending a membership event with broken API backend should return HTTP 500")
            self.assertEqual(response.text, "failure")

def startAPIMock(port):
    """
    Start an GitHub API mocking server on the given `port` and return the
    `mockdata` dict as explained in `apiMockServer()`. Use `updateMockData()`
    to change the contents of the mocking data. The mocking server runs in
    a daemon thread and does not need to be stopped.

    :param port: The port to which the server should bind
    """
    mockdata = {
        'lock': threading.Lock(),
        'retcode': 500,
        'content-type': 'application/json',
        'answers': {},
        'postcallback': None
    }
    thread = threading.Thread(target=apiMockServer,
                              args=(port, mockdata))
    thread.daemon = True
    thread.start()

    return mockdata

def updateMockData(md, retcode=None, contenttype=None, answers=None,
                   postcallback=None):
    """
    Update a mockdata object using appropriate locking. Each of the keyword
    arguments can be `None` (the same as not passing it), which means it should
    not be changed, or a value, which will be copied into the mockdata dict.

    :param md: The mockdata object as returned by `startAPIMock()`
    :param retcode: The HTTP return code for the next requests
    :param contenttype: The Content-Type HTTP header for the next requests
    :param answers: A dictionary mapping paths to objects that will be
                    JSON-encoded and returned for requests to the paths.
    :param postcallback: A callback function called for the next POST requests.
                         Arguments are the requested path and a dict of POST
                         data as returned by `urlparse.parse_qs()`. The
                         callback should return a tuple `(retcode, answer)`
                         where `retcode` is the HTTP return code and `answer`
                         will be JSON-encoded and sent to the client. Note that
                         this callback is run in a different thread, so pay
                         attention to race conditions! To disable the previous
                         callback, set this to an empty string.
    """
    md['lock'].acquire()
    if retcode is not None:
        md['retcode'] = retcode
    if contenttype is not None:
        md['content-type'] = contenttype
    if answers is not None:
        md['answers'] = answers.copy()
    if postcallback is not None:
        md['post-callback'] = postcallback
    md['lock'].release()

def apiMockServer(port, mockdata):
    """
    Thread target for an GitHub API mock server started on the given `port`
    with the given dict of `mockdata`.

    :param port: The port to which the server should bind
    :param mockdata: A dictionary with the keys "lock", "retcode",
                     "content-type" and "answers" where "lock" is
                     a threading.Lock() that will be acquired while the thread
                     reads from the dict, "retcode" is the HTTP return code of
                     the next requests, "content-type" is the Content-Type HTTP
                     header to send with the next requests, and "answers" is
                     a dictionary mapping request paths to objects that should
                     be JSON-encoded and returned. Use `updateMockData()` to
                     update the contents of the mockdata dict.
    """
    httpd = BaseHTTPServer.HTTPServer(('127.0.0.1', port), GitHubAPIMock)
    # Make mockdata available to server
    httpd.mockdata = mockdata
    httpd.serve_forever()


def get_parser():
    parser = argparse.ArgumentParser("Run the test suite for trac-github")
    parser.add_argument('--with-coverage', action='store_true', help="Enable test coverage")
    parser.add_argument('--with-trac-log', action='store_true', help="Display logs of test trac instances")
    parser.add_argument('--virtualenv', help="Path to the virtualenv where Trac is installed")
    parser.add_argument('--git-default-branch', default="main", help="The default branch used in the test repositories")
    return parser


if __name__ == '__main__':
    options, unittest_argv = get_parser().parse_known_args()

    COVERAGE = options.with_coverage
    SHOW_LOG = options.with_trac_log
    GIT_DEFAULT_BRANCH = options.git_default_branch

    if options.virtualenv:
        TRAC_ADMIN_BIN = os.path.join(options.virtualenv, 'bin', TRAC_ADMIN_BIN)
        TRACD_BIN = os.path.join(options.virtualenv, 'bin', TRACD_BIN)
        COVERAGE_BIN = os.path.join(options.virtualenv, 'bin', COVERAGE_BIN)

    TESTDIR = tempfile.mkdtemp(prefix='trac-github-test-')
    print "Starting tests using temporary directory %r" % TESTDIR
    print "Using git version %s" % git_check_output('--version').strip()

    try:
        test_program = unittest.main(argv=[sys.argv[0]] + unittest_argv, exit=False)
    finally:
        shutil.rmtree(TESTDIR)

    if not test_program.result.wasSuccessful():
        sys.exit(1)
    else:
        sys.exit(0)

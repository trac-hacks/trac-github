# -*- coding: utf-8 -*-
#
# This software is licensed as described in the file LICENSE, which
# you should have received as part of this distribution.

import collections
import fnmatch
import hashlib
import hmac
import json
import os
import re
import traceback

from datetime import datetime, timedelta

from subprocess import Popen, PIPE, STDOUT

from genshi.builder import tag

import trac
from trac.cache import cached
from trac.config import ListOption, BoolOption, Option
from trac.core import Component, implements
from trac.perm import IPermissionGroupProvider
from trac.util.translation import _
from trac.versioncontrol.api import is_default, NoSuchChangeset, RepositoryManager
from trac.versioncontrol.web_ui.changeset import ChangesetModule
from trac.web.api import IRequestHandler, RequestDone
from trac.web.auth import LoginModule
from trac.web.chrome import add_warning

def _config_secret(value):
    if re.match(r'[A-Z_]+', value):
        return os.environ.get(value, '')
    elif value.startswith('/') or value.startswith('./'):
        with open(value) as f:
            return f.read().strip()
    else:
        return value


class GitHubLoginModule(LoginModule):

    client_id = Option(
        'github', 'client_id', '',
        doc="""Client ID for the OAuth Application on GitHub.
               Uppercase environment variable name, filename starting with '/' or './', or plain string.""")

    client_secret = Option(
        'github', 'client_secret', '',
        doc="""Client secret for the OAuth Application on GitHub.
               Uppercase environment variable name, filename starting with '/' or './', or plain string.""")

    request_email = BoolOption(
        'github', 'request_email', 'false',
        doc="Request access to the email address of the GitHub user.")

    preferred_email_domain = Option(
        'github', 'preferred_email_domain', '',
        doc="Prefer email address under this domain over the primary address.")

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'github_login'

    def get_navigation_items(self, req):
        if req.authname and req.authname != 'anonymous':
            # Use the same names as LoginModule to avoid duplicates.
            yield ('metanav', 'login', _('logged in as %(user)s',
                                         user=req.authname))
            from pkg_resources import parse_version
            if parse_version(trac.__version__) < parse_version('1.0.2'):
                yield ('metanav', 'logout',
                       tag.a(_('Logout'), href=req.href.github('logout')))
            else:
                yield ('metanav', 'logout',
                       tag.form(tag.div(tag.button(_('Logout'),
                                                   name='logout',
                                                   type='submit')),
                                action=req.href.github('logout'),
                                method='post', id='logout',
                                class_='trac-logout'))
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
        if not self.client_id or not self.client_secret:
            add_warning(req, "GitHubLogin configuration incomplete, missing client_id or client_secret")
            self._redirect_back(req)

        oauth = self._oauth_session(req)
        authorization_url, state = oauth.authorization_url(
            'https://github.com/login/oauth/authorize')
        req.session['oauth_state'] = state
        req.redirect(authorization_url)

    def _do_oauth(self, req):
        try:
            state = req.session['oauth_state']
        except KeyError as exc:
            self._reject_oauth(req, exc)

        oauth = self._oauth_session(req, state)

        # Inner import to avoid a hard dependency on requests-oauthlib.
        import oauthlib
        import requests
        github_oauth_url = os.environ.get("TRAC_GITHUB_OAUTH_URL", "https://github.com/")
        github_api_url = os.environ.get("TRAC_GITHUB_API_URL", "https://api.github.com/")
        try:
            oauth.fetch_token(
                github_oauth_url + 'login/oauth/access_token',
                authorization_response=req.abs_href(req.path_info) + '?' + req.query_string,
                client_secret=_config_secret(self.client_secret))
        except (oauthlib.oauth2.OAuth2Error, requests.exceptions.ConnectionError) as exc:
            self._reject_oauth(req, exc)

        try:
            user = oauth.get(github_api_url + 'user').json()
            # read all required data here to deal with errors correctly
            name = user.get('name')
            email = user.get('email')
            login = user.get('login')
        except Exception as exc: # pylint: disable=broad-except
            self._reject_oauth(
                req, exc,
                reason=_("An error occurred while communicating with the GitHub API"))
        if self.request_email:
            try:
                for item in oauth.get(github_api_url + 'user/emails').json():
                    if not item['verified']:
                        # ignore unverified email addresses
                        continue
                    if (self.preferred_email_domain and
                        item['email'].lower().endswith(
                            '@' + self.preferred_email_domain.lower())):
                        email = item['email']
                        break
                    if item['primary']:
                        email = item['email']
                        if not self.preferred_email_domain:
                            break
            except Exception as exc: # pylint: disable=broad-except
                self._reject_oauth(
                    req, exc,
                    reason=_("An error occurred while retrieving your email address "
                             "from the GitHub API"))
        # Small hack to pass the username to _do_login.
        req.environ['REMOTE_USER'] = login
        # Save other available values in the session.
        req.session.setdefault('name', name or '')
        req.session.setdefault('email', email or '')

        return super(GitHubLoginModule, self)._do_login(req)

    def _reject_oauth(self, req, exc, reason=None):
        self.log.warn("An OAuth authorization attempt was rejected due to an exception: "
                      "%s\n%s" % (exc, traceback.format_exc()))
        if reason is None:
            reason = _("Invalid request. Please try to login again.")
        add_warning(req, reason)
        self._redirect_back(req)

    def _do_logout(self, req):
        req.session.pop('oauth_state', None)
        super(GitHubLoginModule, self)._do_logout(req)

    def _oauth_session(self, req, state=None):
        client_id = _config_secret(self.client_id)
        scope = ['']
        if self.request_email:
            scope = ['user:email']
        redirect_uri = req.abs_href.github('oauth')
        # Inner import to avoid a hard dependency on requests-oauthlib.
        from requests_oauthlib import OAuth2Session
        return OAuth2Session(
            client_id,
            scope=scope,
            redirect_uri=redirect_uri,
            state=state,
        )



class GitHubMixin(Component):

    webhook_secret = Option('github', 'webhook_secret', '',
                            doc="""GitHub webhook secret token.
                                   Uppercase environment variable name, filename starting with '/' or './', or plain string.""")

    def _verify_webhook_signature(self, signature, reqdata):
        if not self.webhook_secret:
            return True
        if not signature:
            return False

        algorithm, _, expected = signature.partition("=")
        supported_algorithms = {
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512
        }
        if algorithm not in supported_algorithms:
            return False

        webhook_secret = _config_secret(self.webhook_secret)

        hmac_hash = hmac.new(
            webhook_secret.encode('utf-8'),
            reqdata,
            supported_algorithms[algorithm])
        computed = hmac_hash.hexdigest()

        return hmac.compare_digest(expected, computed)

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

        if not gh_repo:
            req.args['new'] = rev
            req.args['new_path'] = path
            req.args['reponame'] = reponame
            return super(GitHubBrowser, self).process_request(req)

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

class GitHubCachedAPI(object):
    """
    Abstract base class for a call of the GitHub API. Implements automatic
    caching and deals with errors by re-trying to fetch the data periodically.
    """

    BACKOFF = 60 * 5
    """Timeout in seconds until failed API requests are repeated."""

    def __init__(self, api, env, fullname):
        """
        Setup a cached GitHub API call

        :param api: the `GitHubGroupsProvider` providing API access
        :param env: the `TracEnvironment` context used to cache results
        :param fullname: a unique identifier used to cache this group's
                         members.
        """
        self.api = api
        self.env = env
        self.name = fullname
        # _fullname needs to be a string, not a unicode string, otherwise the
        # cache object won't convert it into a hash.
        self._fullname = fullname.encode('utf-8')
        # next try: immediately
        self._next_update = datetime.now() - timedelta(seconds=10)
        self._cached_result = self._apiresult_error()
        self._first_lookup = True

    def fullname(self):
        """
        Return the unique identifier for this cached object.
        """
        return self.name

    def _apicall_parameters(self):
        """
        Abstract method that returns the API endpoint and all its required
        arguments to query in the format of a sequence where the first index is
        the format string and all following indices contain the format string
        parameters.
        """
        raise NotImplementedError(
            "_apicall_parameters not implemented in %s" % type(self)) # pragma: no cover

    def _apiresult_postprocess(self, json_obj):
        """
        Abstract method that is run on the JSON returned by the GitHub API
        after a successful call. Must return a post-processed version of the
        results to be cached and returned to the user.
        """
        raise NotImplementedError(
            "_apiresult_postprocess not implemented in %s" % type(self)) # pragma: no cover

    def _apiresult_error(self):
        """
        Abstract method that is run if an API call fails. Should return an empty
        'dummy' result that matches the format returned by
        `_apiresult_postprocess`.
        """
        raise NotImplementedError(
            "_apiresult_error not implemented in %s" % type(self)) # pragma: no cover

    @cached('_fullname')
    def _data(self):
        """
        Connect to GitHub API endpoint specified by `_apicall_parameters()` if
        required. If an error occurs, return the result of `_apiresult_error()`
        and set up retrying after a BACKOFF. On success, return the API result
        post-processed by `_apiresult_postprocess()`.

        Do not call this method directly. It does not deal with cache
        invalidation. Instead, call the `data()` function, which does.
        """
        # Disable coverage, because update() will be called during startup, so
        # _first_lookup can never be True here; this is just a safegaurd.
        if self._first_lookup: # pragma: no cover
            self.update()
        return self._cached_result

    def update(self):
        """
        Connect to GitHub API endpoint specified by `_apicall_parameters()`,
        postprocess the result using `_apiresult_postprocess()` and trigger
        a cache update if the API call was successful.

        If an error occurs, cache the empty result generated by
        `_apiresult_error()`. Additionally, set up retrying after a certain
        time.

        Return `True` if the API call was successful, `False` otherwise.

        Call this method directly if you want to invalidate the current cache.
        Otherwise, just call `data()`, which will automatically call `update()`
        if required.
        """
        result = self.api.github_api(*self._apicall_parameters())
        if result is None:
            # an error occurred, try again after BACKOFF
            self._next_update = datetime.now() + timedelta(seconds=self.BACKOFF)
            # assume an empty result until the error disappears
            self._cached_result = self._apiresult_error()
        else:
            # request successful, cache does not expire
            self._next_update = None
            # Write the new result into self._cached_result to be picked up by
            # _data on `del self._data`.
            self._cached_result = self._apiresult_postprocess(result)

        # Don't `del self._data` if it has never been cached, that would create
        # ugly database entries in the cache table.
        if not self._first_lookup:
            del self._data
        else:
            self._first_lookup = False

        # signal success or error
        return result is not None

    def data(self):
        """
        Get a cached post-processed result of a GitHub API call. Uses Trac cache
        to avoid constant querying of the remote API. If a previous API call did
        not succeed, automatically retries after a timeout.
        """
        if self._next_update and datetime.now() > self._next_update:
            self.update()
        return self._data

class GitHubUserCollection(GitHubCachedAPI):
    """
    A cached representation of a collection of users at GitHub. use the
    `members()` method to get a list of GitHub login names that are part of this
    group. To use access the full name of this group, use the `fullname()`
    method.
    """
    def __init__(self, *args, **kwargs):
        super(GitHubUserCollection, self).__init__(*args, **kwargs)
        self.members = self.data

    def _apicall_parameters(self): # pragma: no cover
        return super(GitHubUserCollection, self)._apicall_parameters()

    def _apiresult_postprocess(self, json_obj):
        return [member['login'] for member in json_obj]

    def _apiresult_error(self):
        return []

class GitHubTeam(GitHubUserCollection):
    """
    A cached representation of a team at GitHub. Use the `members()` method to
    get a list of GitHub login names that are part of this group. To access the
    full name of this team, use the `fullname()` method.
    """
    def __init__(self, api, env, org, teamid, slug): # pylint: disable=too-many-arguments
        """
        Create a new team.

        :param api: the `GitHubGroupsProvider` providing API access
        :param env: the `TracEnvironment` context used to cache results
        :param org: the name of the organization of the team
        :param teamid: the GitHub team ID of the team
        :param slug: the GitHub team shortname in URL representation
        """
        self._teamid = teamid
        fullname = '-'.join(['github', org, slug])
        super(GitHubTeam, self).__init__(api, env, fullname)

    def _apicall_parameters(self):
        return ("teams/{}/members", self._teamid)

#class GitHubOrgMembers(GitHubUserCollection):
#    """
#    A cached representation of an organization's members at GitHub. Use the
#    `members()` method to get a list of GitHub login names that are part of this
#    group. To access the full name of this team, use the `fullname()` method.
#    """
#    def __init__(self, api, env, org):
#        """
#        Create a cached representation of the members of an organization.
#
#        :param api: the `GitHubGroupsProvider` providing API access
#        :param env: the `TracEnvironment` context used to cache results
#        :param org: the name of the organization
#        """
#        self._org = org
#        fullname = '-'.join(['github', org])
#        super(GitHubOrgMembers, self).__init__(api, env, fullname)
#
#    def _apicall_parameters(self):
#        return ("orgs/{}/members", self._org)

class GitHubOrgTeams(GitHubCachedAPI):
    """
    A cached representation of an organization's teams at GitHub. Use the
    `teams()` method to get a dictionary of teams in this organization where the
    key is the slug and the value is the team ID.
    """

    def __init__(self, api, env, org):
        """
        Create a cached representation of the teams of an organization.

        :param api: the `GitHubGroupsProvider` providing API access
        :param env: the `TracEnvironment` context used to cache results
        :param org: the name of the organization
        """
        self._org = org
        fullname = '-'.join(['githubteams', org])
        super(GitHubOrgTeams, self).__init__(api, env, fullname)
        self.teams = self.data

    def _apicall_parameters(self):
        return ("orgs/{}/teams", self._org)

    def _apiresult_postprocess(self, json_obj):
        return {team['slug']: team['id'] for team in json_obj}

    def _apiresult_error(self):
        return {}

class GitHubOrg(object):
    """
    A cached representation of an organization at GitHub. Use the `teams()` and
    `members()` methods to get a list of all teams and users in this org,
    respectively.
    """
    def __init__(self, api, env, org):
        self._api = api
        self._env = env
        self._org = org
        self._teamlist = GitHubOrgTeams(api, env, org)
        #self._members = GitHubOrgMembers(api, env, org)
        self._teamobjects = {}

    def teams(self):
        """
        Return a sequence of `GitHubTeam` objects, one for each team in this
        org.
        """
        teams = self._teamlist.teams()

        # find out which teams have been added or removed since the last sync
        current_teams = set(self._teamobjects.keys())
        new_teams = set(teams.keys()) # pylint: disable=no-member
        added = new_teams - current_teams
        removed = current_teams - new_teams

        for team in removed:
            del self._teamobjects[team]
        for team in added:
            self._teamobjects[team] = GitHubTeam(
                self._api, self._env, self._org, teams[team], team) # pylint: disable=unsubscriptable-object
        return self._teamobjects.values()

    def has_team(self, slug):
        """
        Return `True` iff the given `slug` identifies a team of this org.

        :param slug: The GitHub 'slug' of the team to test for.
        """
        return slug in self._teamobjects

    #def fullname(self):
    #    return self._members.fullname()

    #def members(self):
    #    return self._members.members()

    def fullname(self):
        """
        Return the prefix all of this org's imported groups will get in Trac.
        """
        return '-'.join(['github', self._org])

    def members(self):
        """
        Return a list of all users in this organization. Users are identified
        by their login name. Note that this is computed from the teams in the
        organization, because GitHub does not currently offer a WebHook for
        organization membership, so converting org membership would lead to
        stale data.
        """
        allmembers = set()
        for team in self.teams():
            allmembers.update(team.members())
        return sorted(allmembers)

    def update(self):
        """
        Trigger an update and cache invalidation for the list of teams in this
        organization. Returns `True` on success, `False` otherwise.
        """
        success = self._teamlist.update()
        #success &= self._members.update()
        return success

    def update_team(self, slug):
        """
        Trigger an update and cache invalidation for the team identified by the
        given `slug`. Returns `True` on success, `False` otherwise.

        :param slug: The GitHub 'slug' that identifies the team in URLs
        """
        if slug not in self._teamobjects:
            # This case is checked and handled further up, but better be safe
            # than sorry.
            return False # pragma: no cover
        return self._teamobjects[slug].update()

class GitHubGroupsProvider(GitHubMixin, Component):
    """
    Implements the `IPermissionGroupProvider` and `IRequestHandler` extension
    points to provide GitHub teams as groups in Trac and an endpoint for GitHub
    WebHooks to keep the cached groups up to date.
    """
    implements(IPermissionGroupProvider, IRequestHandler)

    organization = Option('github', 'organization', '',
                          doc="Organization from which to pull teams into groups.")

    username = Option('github', 'username', '',
                      doc="GitHub user for accessing organization data.")

    access_token = Option('github', 'access_token', '',
                          doc="""Personal access token for the GitHub user.
                                 Uppercase environment variable name, filename starting with '/' or './', or plain string.""")


    def __init__(self):
        self._org = None
        self._orgteams = None
        self._teams = {}
        self._orgmembers = None

    def github_api(self, url, *args):
        """
        Connect to the given GitHub API URL template by replacing all
        placeholders with the given parameters and return the decoded JSON
        result on success. On error, return `None`.

        :param url: The path to request from the GitHub API. Contains format
                    string placeholders that will be replaced with all
                    additional positional arguments.
        """
        import requests
        import urllib

        github_api_url = os.environ.get("TRAC_GITHUB_API_URL", "https://api.github.com/")
        formatted_url = github_api_url + url.format(*(urllib.quote(str(x)) for x in args))
        access_token = _config_secret(self.access_token)
        self.log.debug("Hitting GitHub API endpoint %s with user %s", formatted_url, self.username) # pylint: disable=no-member
        results = []
        try:
            has_next = True
            while has_next:
                req = requests.get(formatted_url, auth=(self.username, access_token))
                if req.status_code != 200:
                    try:
                        message = req.json()['message']
                    except Exception: # pylint: disable=broad-except
                        message = req.text
                    self.log.error("Error communicating with GitHub API at {}: {}".format( # pylint: disable=no-member
                        formatted_url, message))
                    return None
                results.extend(req.json())
                has_next = 'next' in req.links
                if has_next:
                    formatted_url = req.links['next']['url']
        except requests.exceptions.ConnectionError as rce:
            self.log.error("Exception while communicating with GitHub API at {}: {}".format( # pylint: disable=no-member
                formatted_url, rce))
            return None
        return results

    def _fetch_groups(self):
        # Fetch teams
        if not self._org:
            self._org = GitHubOrg(self, self.env, self.organization) # pylint: disable=no-member
        # Fetch team members
        members = {}
        for team in self._org.teams():
            members[team.fullname()] = team.members()
        # Fetch organization members
        members[self._org.fullname()] = self._org.members()

        # Return data
        data = collections.defaultdict(list)
        for tname, tmembers in members.iteritems():
            self.log.debug("Team members for group %r: %r", tname, tmembers) # pylint: disable=no-member
            for member in tmembers:
                data[member].append(tname)
        return dict(data)

    def update_organization(self):
        """
        Trigger update and cache invalidation for the organization. Returns
        `True` if the update was successful, `False` otherwise.
        """
        if self._org:
            return self._org.update()
        # self._org is created during Trac startup, so there should never
        # be a case where we try to update an org before it's created; this
        # is a sanity check only.
        return False # pragma: no cover

    def update_team(self, slug):
        """
        Trigger update and cache invalidation for the team identified by the
        given `slug`, if any. Returns `True` if the update was successful,
        `False` otherwise.

        :param slug: GitHub 'slug' name for the team to be updated.
        """
        if self._org:
            if not self._org.has_team(slug):
                return self._org.update()
            return self._org.update_team(slug)
        # self._org is created during Trac startup, so there should never
        # be a case where we try to update an org before it's created; this
        # is a sanity check only.
        return False # pragma: no cover

    # IPermissionGroupProvider methods
    def get_permission_groups(self, username):
        """
        Return a list of names of the groups that the user with the specified
        name is a member of. Implements an `IPermissionGroupProvider` API.

        This specific implementation connects to GitHub with a dedicated user,
        fetches and caches the teams and their users configured at GitHub and
        converts the data into a format usable for easy access by username.
        """
        if not self.organization or not self.username or not self.access_token:
            return []
        data = self._fetch_groups()
        if not data:
            self.log.error("No cached groups from GitHub available") # pylint: disable=no-member
            return []
        else:
            return data.get(username, [])

    # IRequestHandler methods
    _request_re = re.compile(r"/github-groups(/.*)?$")
    _debug_request_re = re.compile(r"/github-groups-dump/?$")

    def match_request(self, req):
        """
        Return whether the handler wants to process the given request.
        Implements an `IRequestHandler` API.
        """
        match = self._request_re.match(req.path_info)
        if match:
            return True
        if os.environ.get('TRAC_GITHUB_ENABLE_DEBUGGING', None) is not None:
            debug_match = self._debug_request_re.match(req.path_info)
            if debug_match:
                return True

    def process_debug_request(self, req):
        """
        Debgging helper used for testing, processes the given request and dumps
        the internal state of cached user to group mappings. Note that this is
        only callable if TRAC_GITHUB_ENABLE_DEBUGGING is set in the
        environment.
        """
        req.send(json.dumps(self._fetch_groups()).encode('utf-8'), 'application/json', 200)

    def process_request(self, req):
        """
        Process the given request `req`, implements an `IRequestHandler` API.

        Normally, `process_request` would return a tuple, but since none of
        these requests will return an HTML page, they will all terminate
        without a return value and directly send a response.
        """
        if os.environ.get('TRAC_GITHUB_ENABLE_DEBUGGING', None) is not None:
            debug_match = self._debug_request_re.match(req.path_info)
            if debug_match:
                self.process_debug_request(req)

        if req.method != 'POST':
            msg = u'Endpoint is ready to accept GitHub Organization membership notifications.\n'
            self.log.warning(u'Method not allowed (%s)' % req.method) # pylint: disable=no-member
            req.send(msg.encode('utf-8'), 'text/plain', 405)

        event = req.get_header('X-GitHub-Event')
        supported_events = {
            'ping': self._handle_ping_ev,
            'membership': self._handle_membership_ev
        }

        # Check whether this event is supported
        if event not in supported_events:
            msg = u'Event type %s is not supported\n' % event
            self.log.warning(msg.rstrip('\n')) # pylint: disable=no-member
            req.send(msg.encode('utf-8'), 'text/plain', 400)

        # Verify the event's signature
        reqdata = req.read()
        signature = req.get_header('X-Hub-Signature')
        if not self._verify_webhook_signature(signature, reqdata):
            msg = u'Webhook signature verification failed\n'
            self.log.warning(msg.rstrip('\n')) # pylint: disable=no-member
            req.send(msg.encode('utf-8'), 'text/plain', 403)

        # Decode JSON and handle errors
        try:
            payload = json.loads(reqdata)
        except (ValueError, KeyError):
            msg = u'Invalid payload\n'
            self.log.warning(msg.rstrip('\n')) # pylint: disable=no-member
            req.send(msg.encode('utf-8'), 'text/plain', 400)

        # Handle the event
        try:
            supported_events[event](req, payload)
        except RequestDone:
            # Normal termination, bubble up
            raise
        except Exception: # pylint: disable=broad-except
            msg = (u'Exception occurred while handling payload, '
                   'possible invalid payload\n%s' % traceback.format_exc())
            self.log.warning(msg.rstrip('\n')) # pylint: disable=no-member
            req.send(msg.encode('utf-8'), 'text/plain', 500)

    def _handle_ping_ev(self, req, payload): # pylint: disable=no-self-use
        req.send(payload['zen'].encode('utf-8'), 'text/plain', 200)

    def _handle_membership_ev(self, req, payload):
        # Unfortunately, no events for organization membership, so the idea of
        # converting those is pretty much dead :(

        # Deleting teams sends one notification per team member; the "team" object looks like this:
        # "team": {
        #   "id": 2108536,
        #   "name": "test-team",
        #   "deleted": true
        # }
        # Note the absence of the slug field for deletion requests! Also note
        # that the "deleted" key does *not* exist on standard add and remove
        # updates for teams.
        if 'deleted' in payload['team']:
            # When a team was deleted, update the organization
            success = self.update_organization()
        else:
            # A team was modified, update only this team; if this is a new
            # team, it will automatically trigger an org update.
            success = self.update_team(payload['team']['slug'])
            # Just in case a new team was added, trigger a re-fetch so the new
            # team's members are cached.
            self._fetch_groups()
        if success:
            req.send(u'success'.encode('utf-8'), 'text/plain', 200)
        else:
            req.send(u'failure'.encode('utf-8'), 'text/plain', 500)

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
        path = req.args['path']

        rm = RepositoryManager(self.env)
        reponame, repos, path = rm.get_repository_by_path(path)

        if repos is None or path != '/':
            msg = u'No such repository (%s)\n' % path
            self.log.warning(msg.rstrip('\n'))
            req.send(msg.encode('utf-8'), 'text/plain', 400)

        if req.method != 'POST':
            msg = u'Endpoint is ready to accept GitHub notifications.\n'
            self.log.warning(u'Method not allowed (%s)' % req.method)
            req.send(msg.encode('utf-8'), 'text/plain', 405)

        # Verify the event's signature
        reqdata = req.read()
        signature = req.get_header('X-Hub-Signature')
        if not self._verify_webhook_signature(signature, reqdata):
            msg = u'Webhook signature verification failed\n'
            self.log.warning(msg.rstrip('\n')) # pylint: disable=no-member
            req.send(msg.encode('utf-8'), 'text/plain', 403)

        event = req.get_header('X-GitHub-Event')
        if event == 'ping':
            payload = json.loads(reqdata)
            req.send(payload['zen'].encode('utf-8'), 'text/plain', 200)
        elif event != 'push':
            msg = u'Only ping and push are supported\n'
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
            payload = json.loads(reqdata)
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

        status = 200

        git_dir = git.rev_parse('--git-dir').rstrip('\n')
        hook = os.path.join(git_dir, 'hooks', 'trac-github-update')
        if os.path.isfile(hook):
            output += u'* Running trac-github-update hook\n'
            try:
                p = Popen(hook, cwd=git_dir,
                          stdin=PIPE, stdout=PIPE, stderr=STDOUT,
                          close_fds=trac.util.compat.close_fds)
            except Exception as e:
                output += u'Error: hook execution failed with exception\n%s' % (traceback.format_exc(),)
                status = 500
            else:
                hookoutput = p.communicate(input=reqdata)[0]
                output += hookoutput.decode('utf-8')
                if p.returncode != 0:
                    output += u'Error: hook failed with exit code %d\n' % (p.returncode,)
                    status = 500

        for line in output.splitlines():
            self.log.debug(line)

        if status == 200 and not output:
            status = 204

        req.send(output.encode('utf-8'), 'text/plain', status)


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

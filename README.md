Trac - GitHub integration
=========================

Features
--------

This Trac plugin performs four functions:

1. update the local git mirror used by Trac after each push to GitHub, and
   notify the new changesets to Trac;
2. authenticate users with their GitHub account;
3. direct changeset TracLinks to GitHub's repository browser.
4. sync GitHub teams to Trac permission groups

The notification of new changesets is strictly equivalent to the command
described in Trac's setup guide:

    trac-admin TRAC_ENV changeset added ...

Each feature is implemented in its own component and can be enabled or
disabled (almost) independently.

Requirements
------------

trac-github requires Trac >= 0.12 and the git plugin.

The git plugin [is included](http://trac.edgewall.org/wiki/TracGit) in Trac >=
1.0 — you only have to enable it in `trac.ini`. For Trac 0.12 you have to
[install it](http://trac-hacks.org/wiki/GitPlugin):

    pip install git+https://github.com/hvr/trac-git-plugin.git

Then install trac-github itself:

    pip install trac-github

`requests_oauthlib` is also a requirement if you plan to use `GitHubLoginModule`:

    pip install requests_oauthlib

Setup
-----

_Warning: the commands below are provided for illustrative purposes. You'll
have to adapt them to your setup._

### Post-commit hook

**`tracext.github.GitHubPostCommitHook`** implements a post-commit hook called
by GitHub after each push.

It updates the git mirror used by Trac, triggers a cache update and notifies
components of the new changesets. Notifications are used by Trac's [commit
ticket updater](http://trac.edgewall.org/wiki/CommitTicketUpdater) and
[notifications](http://trac.edgewall.org/wiki/TracNotification).

First, you need a mirror of your GitHub repository, writable by the webserver,
for Trac's use:

    cd /home/trac
    git clone --mirror git://github.com/<user>/<project>.git
    chown -R www-data:www-data <project>.git

Ensure that the user under which your web server runs can update the mirror:

    su www-data
    git --git-dir=/home/trac/<project>.git remote update --prune

Now edit your `trac.ini` as follows to configure both the git and the
trac-github plugins:

    [components]
    tracext.github.GitHubPostCommitHook = enabled
    tracext.github.GitHubMixin = enabled
    tracopt.ticket.commit_updater.* = enabled
    tracopt.versioncontrol.git.* = enabled

    [git]
    trac_user_rlookup = enabled

    [github]
    repository = <user>/<project>

    [trac]
    repository_sync_per_request =   # Trac < 1.2

    [repositories]
    .dir = /home/trac/<project>.git
    .type = git
    .sync_per_request = false  # Trac >= 1.2

In Trac 0.12, use `tracext.git.* = enabled` instead of
`tracopt.versioncontrol.git.* = enabled`.

`tracopt.ticket.commit_updater.*` activates the [commit ticket
updater](http://trac.edgewall.org/wiki/CommitTicketUpdater). It isn't
required, but it's the most useful feature enabled by trac-github.

The author names that Trac caches are of the pattern
`Full Name <email@domain.com>`. The `trac_user_rlookup` option enables
reverse mapping from email address to Trac user id. This is necessary
for commit ticket updater to function, and for `[trac]` options like
[show_full_names](https://trac.edgewall.org/wiki/TracIni#trac-show_full_names-option)
and
[show_email_addresses](https://trac.edgewall.org/wiki/TracIni#trac-show_email_addresses-option)
to be effective.

Reload the web server and your repository should appear in Trac.

Perform an initial synchronization of the cache.

    trac-admin $env repository resync "(default)"

Note that `"(default")` will need to be replaced with the repository
name if a named repository is used. See the [Trac documentation]
(https://trac.edgewall.org/wiki/TracRepositoryAdmin#ReposTracIni)
for more information.

Browse to the home page of your project in Trac and append `/github` to the
URL. Append `/github/<reponame>` if you have a named repository
(see [multiple repositories](#multiple-repositories)). You should see the
following message:

    Endpoint is ready to accept GitHub notifications.

This is the URL of the endpoint.

If you get a Trac error page saying "No handler matched request to /github"
instead, the plugin isn't installed properly. Make sure you've followed the
installation instructions correctly and [search Trac's logs]
(https://trac.edgewall.org/wiki/TracTroubleshooting#ChecktheLogs) for errors.

Now go to your project's settings page on GitHub. In the "Webhooks & Services"
tab, click "Add webhook". Put the URL of the endpoint in the "Payload URL"
field and set the "Content type" to `application/json`. Click "Add webhook".

If you click on the webhook you just created, at the bottom of the page, you
should see that a "ping" payload was successufully delivered to Trac

Optionally, you can run additional actions every time GitHub triggers a webhook
by placing a custom executable script at `<project>.git/hooks/trac-github-update`.

### Authentication

**`tracext.github.GitHubLoginModule`** provides authentication through
GitHub's OAuth API. It obtains users' names and email addresses after a
successful login if they're public and saves them in the preferences.

To use this module, your Trac instance must be served over HTTPS. This is a
requirement of the OAuth2 standard.

Go to your accounts settings page on GitHub. From the *OAuth Application*
page, click the *Developer applications* tab and *Register new application*.
For the "Authorization callback URL", put the URL of the homepage of your
project in Trac, starting with `https://`, and append `/github/oauth`.
In other words, this is the URL of the endpoint you used above plus `/oauth`
Then click *Register application*.

You're redirected to your newly created application's page, which provides a
Client ID and a Client Secret.

Now edit edit `trac.ini` as follows:

    [components]
    trac.web.auth.LoginModule = disabled
    tracext.github.GitHubLoginModule = enabled

    [github]
    client_id = <your Client ID>
    client_secret = <your Client Secret>

This example disables `trac.web.auth.LoginModule`. Otherwise different users
could authenticate with the same username through different systems!

If it's impractical to set the Client ID and Client Secret in the Trac
configuration file, you have some alternatives:

- If `client_secret` matches `[A-Z_]+` (uppercase only), trac-github will use
  the content of the corresponding environment variable as client secret.
- If `client_secret` starts with '/' or './', trac-github will interpret it as
  a file name and use the contents of that file as client secret.
- If `client_secret` is anything else, trac-github will use it as is.

By default the preferences will use the public email address of the
authenticated GitHub user. If the public email address is not set, the field
will be empty. If the email address is important for your Trac installation
(for example for notifications), the `request_email` option can be set to
always request access to all email addresses from GitHub. The primary address
will be stored in the preferences on the first login.

    [github]
    request_email = true
    preferred_email_domain = example.org

if specified, the first address matching the optional `preferred_email_domain`
will be used instead of the primary address.

Note that the Trac mail address will only be initialized on the first login.
Users can still change or remove the email address from their Trac account.

### Browser

**`tracext.github.GitHubBrowser`** redirects changeset TracLinks to
the GitHub repositor browser. It requires the post-commit hook.

To enable it, edit `trac.ini` as follows:

    [components]
    trac.versioncontrol.web_ui.browser.BrowserModule = disabled
    trac.versioncontrol.web_ui.changeset.ChangesetModule = disabled
    trac.versioncontrol.web_ui.log.LogModule = disabled
    tracext.github.GitHubBrowser = enabled
    tracext.github.GitHubMixin = enabled

Since it replaces standard URLs of Trac, you must disable three components in
`trac.versioncontrol.web_ui`, as shown above.

With the `BROWSER_MODULE` disabled the `BROWSER_VIEW` and `FILE_VIEW` permissions will no longer be available. The permissions are checked when rendering files in the timeline, when `[timeline]` `changeset_show_files` is non-zero. Enabling the permisison policy will make the list of files visible in the timeline for users that possess `CHANGESET_VIEW`.

Add the permission policy before `DefaultPermissionsPolicy`. It is usually correct to make it the first entry in the list.

The following will be correct for a Trac 1.2 installation that had the default value for `permission_policies`.

    [trac]
    permission_policies = GitHubPolicy, ReadonlyWikiPolicy, DefaultPermissionPolicy, LegacyAttachmentPolicy

### Group Synchronization

GitHub teams can be synced to Trac permission groups using
**`tracext.github.GitHubGroupsProvider`**. It uses a dedicated GitHub user and
their personal access token to synchronize group memberships. Note that this
user must have permission to read all your organization's teams. Additionally,
this module implements a Webhook endpoint to keep the groups synchronized at
all times.

Register a new user for the synchronization or re-use an existing bot user.
Make sure the bot user has owner privileges for your organization. Go to
*Settings* > *Developer settings* > *Personal access tokens* and click
*Generate a new token*. Make sure `read:org` under `admin:org` is checked and
submit. Copy the displayed hex string.

Now edit edit `trac.ini` as follows:

    [components]
    tracext.github.GitHubGroupsProvider = enabled
    tracext.github.GitHubMixin = enabled

    [github]
	organization = <your organization name>
	username = <your sync user's username>
	access_token = <paste the generated access token>

This should give you an initial working synchronization of your organization's
teams, but no automatic update. Because the cache does not expire, restarting
trac is your only option to force a resync. If the synchronization does not
work as expected, enable debug logging in Trac and check the logfile.

Next, you should configure a Webhook to keep your groups up to date. Browse to
the home page of your project in Trac and append `/github-groups` to the URL.
You should see the following message:

    Endpoint is ready to accept GitHub Organization membership notifications.

This is the URL of the endpoint.

Log in as an organization owner and find the *Webhooks* panel in the
organization's settings. Add a new webhook and use the endpoint URL in the
*Payload URL* field. Use `application/json` as *Content type*. Leave the secret
empty for now, and select *Membership* from the list of individual events.
Disable the *Push* event, since this endpoint will not handle it. Add the
webhook, open it and check the list of recent deliveries. It should have sent
a successful ping event.

Finally, you should secure your webhook. Generate a random shared secret, for
example using `/dev/urandom` and a hash algorithm:

    dd if=/dev/urandom of=/dev/stdout bs=16 count=16 | openssl dgst -sha256

Copy the secret, edit `trac.ini` and add

    [github]
	webhook_secret = <paste the generated secret>

Go to your webook's settings on GitHub again and paste the secret in the
*Secret* field. After saving, select the ping event from the recent deliveries
list and click *Redeliver* to make sure the shared secret works.

The synchronized groups will be named `github-${orgname}-${team_slug}`, e.g.
for the *extraordinary league* team of the *people* organization, the group in
Trac will be named `github-people-extraordinary-league`.

An additional `github-${orgname}` group will contain all members of all teams
in your organization. Note that members of your organization that are not part
of a team will not be part of this group. This limitation is necessary because
GitHub does not (yet) provide a notification mechanism for changes in
organization membership.

If you do not want to store the API secrets for `access_token` and
`webhook_secret` in trac.ini, you can use the same alternatives as for
`client_id` and `client_secret` documented [above](#authentication).


Advanced setup
--------------

### Branches

By default, trac-github notifies all commits to Trac. But you may not wish
to trigger notifications for commits on experimental branches until they're
merged, for example.

You can configure trac-github to only notify commits on some branches:

    [github]
    branches = master

You can provide more than one branch name, and you can use [shell-style wildcards]
(https://docs.python.org/2.7/library/fnmatch.html):

    [github]
    branches = master stable/*

This option also restricts which branches are shown in the timeline.

Besides, trac-github uses relies on the 'distinct' flag set by GitHub to
prevent duplicate notifications when you merge branches.

### Multiple repositories

If you have multiple repositories, you must tell Trac how they're called on
GitHub:

    [github]
    repository = <user>/<project>               # default repository
    <reponame>.repository = <user>/<project>    # for each extra repository
    <reponame>.branches = <branches>            # optional

When you configure the webhook URLs, append the name used by Trac to identify
the repository:

    http://<trac.example.com>/github/<reponame>

### Private repositories

If you're deploying trac-github on a private Trac instance to manage private
repositories, you have to take a few extra steps to allow Trac to pull changes
from GitHub. The trick is to have Trac authenticate with a SSH key referenced
as a deployment key on GitHub.

All the commands shown below must be run by the webserver's user, eg www-data:

    $ su www-data

Generate a dedicated SSH key with an empty passphrase and obtain the public
key:

    $ ssh-keygen -f ~/.ssh/id_rsa_trac
    $ cat ~/.ssh/id_rsa_trac.pub

Make sure you've obtained the public key (`.pub`). It should begin with
`ssh-rsa`. If you're seeing an armored blob of data, it's the private key!

Go to your project's settings page on GitHub. In the Deploy Keys tab, add the
public key.

Edit the SSH configuration for the `www-data` user:

    $ vi ~/.ssh/config

Append the following lines:

    Host github-trac
    Hostname github.com
    IdentityFile ~/.ssh/id_rsa_trac

Edit the git configuration for the repository:

    $ cd /home/trac/<project>.git
    $ vi config

Replace `github.com` in the `url` parameter by the `Host` value you've added
to the SSH configuration:

    url = git@github-trac:<user>/<project>.git

Make sure the authentication works:

    $ git remote update --prune

Since GitHub doesn't allow reusing SSH keys across repositories, you have to
generate a new key and pick a new `Host` value for each new repository.

Development
-----------

In a [virtualenv](https://virtualenv.pypa.io/en/stable/), install the 
requirements:

    pip install trac
    pip install coverage      # if you want to run the tests under coverage
    pip install -e .

or, instead of `pip install trac`:

    pip install trac==0.12.7
    pip install -e git+https://github.com/hvr/trac-git-plugin.git

*The version of PyGIT bundled with `trac-git-plugin` doesn't work with
the `git` binary shipped with OS X. To fix it, in the virtualenv, edit
`src/tracgit/tracext/git/PyGIT.py` and replace `_, _, version =
v.strip().split()` with `version = v.strip().split()[2]`.*

Run the tests with:

    ./runtests.py

Display Trac's log during the tests with:

    ./runtests.py --with-trac-log

Run the tests under coverage with:

    coverage erase
    ./runtests.py --with-coverage
    coverage html

If you put a breakpoint in the test suite, you can interact with Trac's web
interface at [http://localhost:8765/](http://localhost:8765/) and with the git
repositories through the command line.

Running `tracd` ([TracStandalone](https://trac.edgewall.org/wiki/TracStandalone)) 
is the most convenient way to develop Trac from your workstation. Your local 
instance of `tracd` can be exposed to the internet using [ngrok]
(https://ngrok.com/). Download, extract and run `ngrok`:

    unzip ngrok-*.zip
    ngrok http 8000 --log ngrok.log

The `ngrok` window will display a forwarding URL, for example:

    Forwarding                    https://abd75d3e.ngrok.io -> localhost:8000

The URL will be used for configuring the webhook and will change 
each time you restart ngrok. See the [ngrok docs]
(https://ngrok.com/docs) for additional configuration options.

Run `tracd` on the port you specified to `ngrok`:

    tracd -r -s -p 8000 /path/to/trac/env

Complete the standard configuration steps in [setup](#setup). See
the [Trac docs]
(https://trac.edgewall.org/wiki/TracDev/DevelopmentEnvironmentSetup)
for additional information on setting up a Trac development environment.


Release Steps
-------------

You need to be an owner of the [package on PyPI]
(https://pypi.python.org/pypi/trac-github) to create a release. The steps assume
you've configured a [.pypirc file]
(https://packaging.python.org/distributing/#create-an-account).

1. Update the [changelog](#changelog).
2. Set `tag_build = ` in [setup.cfg]
(https://github.com/trac-hacks/trac-github/blob/master/setup.cfg)
3. Create the release:

    ```
    $ virtualenv pve
    $ . pve/bin/activate
    $ pip install -U pip wheel setuptools twine
    $ git clone https://github.com/trac-hacks/trac-github.git
    $ cd trac-github
    $ git tag <version>
    $ git push --tags
    $ rm -r dist  # if reusing virtualenv, but using a new virtualenv is advised
    $ python setup.py sdist bdist_wheel
    $ twine upload dist/*.tar.gz dist/*.whl
    ```
    
Known issues
------------

Once in a while, a notification doesn't appear in Trac.

Usually, that happens when Trac fails to find the commit that triggered the
notification, even though it just synchronized the git repository with GitHub.

You can confirm that in your webhook's configuration page on GitHub. Scroll
down to "Recent Deliveries" and look at the delivery that failed. In the
"Response" tab, you should see a response body such as:

    Running hook on (default)
    * Updating clone
    * Synchronizing with clone
    * Unknown commit ...

Simply click "Redeliver". Then missing notification should appear in Trac and
the response body should change to:

    Running hook on (default)
    * Updating clone
    * Synchronizing with clone
    * Adding commit ...

This problem isn't well understood. It may be related to Trac's access layer
for git repositories. If you have an idea to fix it, please submit a patch!

Changelog
---------

### 2.3

* Support webhook signature verification for post commit hooks. (#114)
* Allow passing a GitHub push webhook payload to a custom script per repository
  that will receive GitHub's JSON on stdin for further postprocessing. (#114)
* Improve interaction with both GitHub and non-GitHub repositories on a single
  instance by delegating /changeset to the original ChangesetModule if enabled
  and the GitHub module did not match. (#110)
* Optionally request access to non-public email addresses from GitHub and allow
  selection of an address by specifying a preferred domain. (#105)
* Support synchronizing GitHub teams to Trac permission groups. (#104)

### 2.2

* CSRF security fix: add verification of OAuth state parameter.

### 2.1.5

* Support reading the GitHub OAuth secret from a file.
* Trap `MissingTokenError` and add a warning.

### 2.1.4

* Make `requests-oauthlib` a requirement for `GitHubLoginModule`.
* Improve description of functionality provided by plugin.

### 2.1.3

* Fix GitHub login failure with recent versions of oauthlib.
* Fix logout after GitHub login on Trac >= 1.0.2.
* Update configuration example to reflect Trac's current best practice.
* Move the project to the trac-hacks organization on GitHub.

### 2.1.2

* Make `tracext` a namespace package to support installation as an egg.
* Improve responses when there's no repository at a requests's target URL.

### 2.1.1

* Fix GitHub login failure when a user has no email on GitHub.

### 2.1

* Add support for GitHub login.

### 2.0

* Adapt to GitHub's new webhooks.

When you upgrade from 1.x, you must change your webhooks settings on GitHub to
use the application/vnd.github.v3+json format.

### 1.2

* Add support for cached repositories.

### 1.1

* Add support for multiple repositories.
* Add an option to restrict notifications to some branches.
* Try to avoid duplicate notifications (GitHub doesn't document the payload).
* Use GitHub's generic webhook URLs.
* Use a git mirror instead of a bare clone.

### 1.0

* Public release.

License
-------

This plugin is released under the BSD license.

It was initially written for [Django's Trac](https://code.djangoproject.com/).
Prominent users include [jQuery Trac](https://bugs.jquery.com), [jQuery UI
Trac](https://bugs.jqueryui.com) and [MacPorts
Trac](https://trac.macports.org).

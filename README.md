Trac - GitHub integration
=========================

Features
--------

This Trac plugin performs three functions:

1. update the local git mirror used by Trac after each push to GitHub, and
   notify the new changesets to Trac;
2. authenticate users with their GitHub account;
3. direct changeset TracLinks to GitHub's repository browser.

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

    pip install -e git://github.com/hvr/trac-git-plugin.git#egg=TracGit-dev

Then install trac-github itself:

    pip install trac-github

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
    tracopt.ticket.commit_updater.* = enabled
    tracopt.versioncontrol.git.* = enabled

    [git]
    trac_user_rlookup = enabled

    [github]
    repository = <user>/<project>

    [repositories]
    .dir = /home/trac/<project>.git
    .type = git

In Trac 0.12, use `tracext.git.* = enabled` instead of
`tracopt.versioncontrol.git.* = enabled`.

`tracopt.ticket.commit_updater.*` activates the [commit ticket
updater](http://trac.edgewall.org/wiki/CommitTicketUpdater). It isn't
required, but it's the most useful feature enabled by trac-github.

The author names that Trac caches are of the pattern
`Full Name <email@domain.com>`. The `trac_user_rlookup` option enables
reverse mapping from email address to Trac user id. This is necessary
for commit ticket updater to function, and for `[trac]` options like
[show_full_names](https://trac.edgewall.org/wiki/TracIni#/show_full_names)
and
[show_email_addresses](https://trac.edgewall.org/wiki/TracIni#/show_email_addresses)
to be effective.

Reload the web server and your repository should appear in Trac.

Perform an initial synchronization of the cache.

    trac-admin $env repository resync "(default)"

Note that `"(default")` will need to be replaced with the repository
name if a named repository is used. See the
[Trac documentation](TracRepositoryAdmin#ReposTracIni) for more information.

Browse to the home page of your project in Trac and append `/github` to the
URL. You should see the following message:

    Endpoint is ready to accept GitHub notifications.

This is the URL of the endpoint.

If you get a Trac error page saying "No handler matched request to /github"
instead, the plugin isn't installed properly. Make sure you've followed the
installation instructions correctly and search Trac's logs for errors.

Now go to your project's settings page on GitHub. In the "Webhooks & Services"
tab, click "Add webhook". Put the URL of the endpoint in the "Payload URL"
field and set the "Content type" to `application/json`. Click "Add webhook".

If you click on the webhook you just created, at the bottom of the page, you
should see that a "ping" payload was successufully delivered to Trac

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

- If `client_secret` is an hexadecimal value, trac-github will use it as is.
- If `client_secret` is an uppercase value, trac-github will use the content
  of the corresponding environment variable as client secret.
- If `client_secret` is anything else, trac-github will interpret it as a file
  name and use the contents of that file as client secret.

By default the preferences will use the public email address of the
authenticated GitHub user. If the public email address is not set, the field
will be empty. If the email address is important for your Trac installation
(for example for notifications), the request_email option can be set to always
request access to all email addresses from GitHub. The primary address will be
stored in the preferences on the first login.

    [github]
    request_email = true

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

Since it replaces standard URLs of Trac, you must disable three components in
`trac.versioncontrol.web_ui`, as shown above.

Advanced setup
--------------

### Branches

By default, trac-github notifies all commits to Trac. But you may not wish
to trigger notifications for commits on experimental branches until they're
merged, for example.

You can configure trac-github to only notify commits on some branches:

    [github]
    branches = master

You can provide more than one branch name, and you can use [shell-style
wildcards](http://docs.python.org/library/fnmatch):

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

In a [virtualenv](http://www.virtualenv.org/), install the requirements:

    pip install trac
    pip install coverage      # if you want to run the tests under coverage
    pip install -e .

or, instead of `pip install trac`:

    pip install trac==0.12.4
    pip install -e git://github.com/hvr/trac-git-plugin.git#egg=TracGit-dev

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

It was initially written for [Django's Trac](https://code.djangoproject.com/). Prominent users include [jQuery Trac](https://bugs.jquery.com) and [jQuery UI Trac](https://bugs.jqueryui.com).

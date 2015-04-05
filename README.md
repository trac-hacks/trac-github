Trac - GitHub integration
=========================

Features
--------

This Trac plugin performs four functions:

1. update the local git mirror used by Trac after each push to GitHub, and
   notify the new changesets to Trac;
2. authenticate users with their GitHub account;
3. replace Trac's built-in browser by GitHub's.
4. Sync any new GitHub issues and pull requests into Trac tickets.

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

    [github]
    repository = <user>/<project>

    [trac]
    repository_dir = /home/trac/<project>.git
    repository_type = git

In Trac 0.12, use `tracext.git.* = enabled` instead of
`tracopt.versioncontrol.git.* = enabled`.

`tracopt.ticket.commit_updater.*` activates the [commit ticket
updater](http://trac.edgewall.org/wiki/CommitTicketUpdater). It isn't
required, but it's the most useful feature enabled by trac-github.

Reload the web server and your repository should appear in Trac.

Browse to the home page of your project in Trac and append `/github` to the
URL. You should see the following message:

    Endpoint is ready to accept GitHub notifications.

This is the URL of the endpoint.

If you get a Trac error page saying "No handler matched request to /github"
instead, the plugin isn't installed properly. Make sure you've followed the
installation instructions correctly and search Trac's logs for errors.

Now go to your project's settings page on GitHub. In the "Webhooks & Services"
tab, click "Add webhook". Put the URL of the endpoint in the "Payload URL"
field and set the "Payload version" to application/vnd.github.v3+json. Then
click "Add webhook".

If you click on the webhook you just created, at the bottom of the page, you
should see that a "ping" payload was successufully delivered to Trac

### Authentication

**`tracext.github.GitHubLoginModule`** provides authentication through
GitHub's OAuth API. It obtains users' names and email addresses after a
successful login if they're public and saves them in the preferences.

To use this module, your Trac instance must be served over HTTPS. This is a
requirement of the OAuth2 standard.

Go to your accounts's settings page on GitHub. In the "Application" tab, click
"Register new application" and fill in the form. The "Authorization callback
URL", put the URL of the homepage of your project in Trac, starting with
`https://`, and append `/github/oauth`. In other words, this is the URL of the
endpoint you used above plus `/oauth`. Then click "Register application".

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

### Browser

**`tracext.github.GitHubBrowser`** replaces Trac's built-in browser by
redirecting to the corresponding pages on GitHub. It depends on the
post-commit hook.

To enable it, edit `trac.ini` as follows:

    [components]
    trac.versioncontrol.web_ui.browser.BrowserModule = disabled
    trac.versioncontrol.web_ui.changeset.ChangesetModule = disabled
    trac.versioncontrol.web_ui.log.LogModule = disabled
    tracext.github.GitHubBrowser = enabled

Since it replaces standard URLs of Trac, you must disable three components in
`trac.versioncontrol.web_ui`, as shown above.

### Syncing Issues and Pull Requests

**`tracext.github.GitHubIssueHook`** implements a a few GitHub hooks called
when a new issue or pull request is opened, commented on, or changed.

It will open a new Trac ticket with the corresponding issue or pull request
title and description, setting the reporter to "username (GitHub)". It will use
all default ticket fields for everything else. It will also automatically
attach a patch file for any pull requests, along with any new patches when
someone pushes new commits to any existing pull request.

Additionally, if any comments are left on the issue or pull request (including
inline patch comments on pulls) on GitHub, they will be posted to the Trac
ticket as well.

Unlike the post-commit hook used for syncing any GitHub repos, these hooks are
required to configure a hook "secret" used to verify that the hooks were sent
from GitHub. This is to prevent spam tickets and comments. So first, you should
generate a random secret to be used with this hook. Ideally, it should be a
random string about 40 characters long containing only `[0-9a-f]` characters.
You can generate this on the command line by running this if you prefer:

    $ ruby -rsecurerandom -e 'puts SecureRandom.hex(20)'

It should look like this (don't just use this string though!):
`cc6f7dddec47e4e10a423dcfbab5c102f506f72d`

Save that somewhere safe, you will use this as your `hook_secret`.

Edit your `trac.ini` as follows to configure syncing:

    [components]
    tracext.github.GitHubIssueHook = enabled

    [github]
    hook_secret = <your_hook_secret_here>

Reload the web server, browse to the home page of your project in Trac and
append `/github-issues` to the URL. You should see the following message:

    Endpoint is ready to accept GitHub notifications.

This is the URL of the issues endpoint we'll use for the hook.

If you get a Trac error page saying "No handler matched request to
/github-issues" instead, the plugin isn't installed properly. Make sure you've
followed the installation instructions correctly and search Trac's logs for
errors.

This hook supports creating tickets for multiple GitHub repos if you want it to
watch issues and pull requests from several of them at the same time. So it's
possible to create an "organization hook", which will fire for all organization
repositories, or just create any number of "repository hooks" for the repos you
want it to watch. The configuration for either is exactly the same.

Go to your organization's or repository's settings page on GitHub. In the
"Webhooks & Services" tab, click "Add webhook". Put the URL of the endpoint in
the "Payload URL" field, leave the "Content type" as "application/json", and set
the "Secret" to the 40 character `hook_secret` you generated earlier. Now select
the "Let me select individual events" radio option, and check the following
hooks: "Issue Comments", "Issues", "Pull Request", and "Pull Request review
comment". Then click "Add webhook", and you're done.

If you click on the webhook you just created, at the bottom of the page, you
should see that a "ping" payload was successufully delivered to Trac.

If you already have existing issues or pull requests, they will not be synced
to Trac. Only new issues and pull requests will be synced.

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

* Add support for syncing issues and pull requests.

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

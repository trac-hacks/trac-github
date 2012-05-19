Trac - GitHub integration
=========================

Features
--------

This Trac plugin performs three functions:

- notify Trac of new commits after each push to GitHub;
- update the local clone used by Trac after each push (optional);
- replace Trac's built-in browser by GitHub's (optional).

The notification of new commits is strictly equivalent to the command described
in Trac's setup guide:

    trac-admin TRAC_ENV changeset added ...

These features are comparable to https://github.com/davglass/github-trac.
However trac-github has three advantages:

- it has no external dependencies;
- it makes better use of Trac's APIs;
- it has a smaller codebase.

Requirements
------------

trac-github requires Trac >= 0.12.

Trac >= 0.13 [includes the git plugin](http://trac.edgewall.org/wiki/TracGit).
You only need to enable it in `trac.ini`. For older versions of Trac, you have
to [install the the git plugin](http://trac-hacks.org/wiki/GitPlugin). Hint:

    pip install -e git://github.com/hvr/trac-git-plugin.git#egg=TracGit-dev

Setup
-----

_Warning: the commands below are provided for illustrative purposes. You'll have
to adapt them to your setup._

You need a clone of your GitHub repository for Trac's use. If you intend to
enable autofetch, the clone must be writable by the webserver. For the best
results, create a bare clone, like this:

    cd /home/trac
    git clone --bare --no-checkout git://github.com/<user>/<project>.git
    chown -R www-data:www-data <project.git>

Ensure that the user under which your web server runs can fetch into this
repository:

    su www-data
    git --git-dir=/home/trac/<project.git> fetch

Now edit your `trac.ini` as follows to configure both the git and the
trac-github plugins:

    [components]
    trac.versioncontrol.web_ui.browser.BrowserModule = disabled
    trac.versioncontrol.web_ui.changeset.ChangesetModule = disabled
    trac.versioncontrol.web_ui.log.LogModule = disabled
    tracext.git.* = enabled
    tracext.github.* = enabled

    [github]
    autofetch = enabled
    repository = <user>/<project>
    token = <secret token>

    [trac]
    repository_dir = /home/trac/<project.git>
    repository_type = git

Reload the configuration, and your project should appear in Trac.

Finally, go to your project's administration page on GitHub. In the service
hooks tab, select the Trac hook. Enter the root URL of your Trac installation
and the same token as in `trac.ini`. This token is a shared secret that ensures
that only GitHub can trigger the post-commit hook.

Advanced use
------------

trac-github provides two components that you can enable separately.

* **`tracext.github.GitHubBrowser`** replaces Trac's built-in browser by
  redirects to the corresponding pages on Github. Since it replaces standard
  URLs of Trac, if you enable this pluign, you must disable three components in
  `trac.versioncontrol.web_ui`, as shown in the configuration file above.
* **`tracext.github.GitHubPostCommitHook`** is the post-commit hook called by
  GitHub. If the `autofetch` option is enabled, the local clone used by Trac
  will be updated. Specifically, the branches will point to the same commits as
  on GitHub. The plugin will then trigger a cache update and notify components
  about the new changesets. This is useful in combination with Trac's [commit
  ticket updater](http://trac.edgewall.org/wiki/CommitTicketUpdater) and
  [notifications](http://trac.edgewall.org/wiki/TracNotification).

License
-------

This plugin is released under the BSD license.

It was written for [Django's Trac](https://code.djangoproject.com/).

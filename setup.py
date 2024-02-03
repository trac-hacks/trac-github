#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This software is licensed as described in the file LICENSE, which
# you should have received as part of this distribution.

from setuptools import setup, find_packages

setup(
    name='trac-github',
    version='2.4',
    author='Aymeric Augustin',
    author_email='aymeric.augustin@m4x.org',
    url='https://github.com/trac-hacks/trac-github',
    description='Trac - GitHub integration',
    download_url='https://pypi.python.org/pypi/trac-github',
    packages=find_packages(),
    namespace_packages=['tracext'],
    platforms='all',
    license='BSD',
    install_requires=[
        'six==1.16.0',
    ],
    extras_require={'oauth': ['requests_oauthlib >= 0.5']},
    entry_points={'trac.plugins': [
        'github.browser = tracext.github:GitHubBrowser',
        'github.loginmodule = tracext.github:GitHubLoginModule[oauth]',
        'github.postcommithook = tracext.github:GitHubPostCommitHook',
        'github.groups = tracext.github:GitHubGroupsProvider',
    ]},
    test_suite='runtests',
    tests_require='lxml',
)

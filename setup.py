from setuptools import setup

setup(
    name='trac-github',
    version='2.2',
    author='Aymeric Augustin',
    author_email='aymeric.augustin@m4x.org',
    url='https://github.com/trac-hacks/trac-github',
    description='Trac - GitHub integration',
    download_url='https://pypi.python.org/pypi/trac-github',
    packages=['tracext'],
    platforms='all',
    license='BSD',
    extras_require={'oauth': ['requests_oauthlib >= 0.5']},
    entry_points={'trac.plugins': [
        'github.browser = tracext.github:GitHubBrowser',
        'github.loginmodule = tracext.github:GitHubLoginModule[oauth]',
        'github.postcommithook = tracext.github:GitHubPostCommitHook',
    ]},
)

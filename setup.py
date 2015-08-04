from setuptools import setup

setup(
    name='trac-github',
    version='2.1.1',
    author='Aymeric Augustin',
    author_email='aymeric.augustin@m4x.org',
    url='https://github.com/trac-hacks/trac-github',
    description='Trac - GitHub integration',
    download_url='http://pypi.python.org/pypi/trac-github',
    packages=['tracext'],
    namespace_packages=['tracext'],
    platforms='all',
    license='BSD',
    entry_points={'trac.plugins': ['github = tracext.github']},
)

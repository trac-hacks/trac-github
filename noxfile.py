import sys

import nox

if sys.version_info.major == 2:
    TRAC_VERSIONS = ["1.4.4", "1.2.6"]
    PYTHON_VERSIONS = ["2.7"]
else:
    TRAC_VERSIONS = ["1.6"]
    PYTHON_VERSIONS = ["3.7", "3.8", "3.9", "3.10", "3.11", "3.12"]  # duplicated in runtests.yml


@nox.session(python=PYTHON_VERSIONS)
@nox.parametrize("trac", TRAC_VERSIONS)
def runtests(session, trac):
    session.install("-r", "requirements_test.txt")
    session.install("Trac==%s" % trac)
    session.run("python", "--version")
    session.run("python", "runtests.py", *session.posargs)

import sys

import nox

if sys.version_info.major == 2:
    TRAC_VERSIONS = ["1.4.4", "1.2.6"]
else:
    TRAC_VERSIONS = ["1.6"]


@nox.session
@nox.parametrize("trac", TRAC_VERSIONS)
def runtests(session, trac):
    session.install("-r", "requirements_test.txt")
    session.install("Trac==%s" % trac)
    session.run("python", "runtests.py", *session.posargs)

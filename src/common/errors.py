# flake8: noqa: E501
#
#   (C) Sebastian Weigmann, 2025
#   This software is released under:
#   GNU GENERAL PUBLIC LICENSE, Version 3
#   Please find the full text in LICENSE.

# generic imports
import sys

# specific imports
from enum import IntEnum, StrEnum


# exit codes
class EXIT(IntEnum):
    OK = 0
    GENERIC = 1
    ARGPARSE = 2


# error levels
class ERRLVL(IntEnum):
    CRIT = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    INFNT = 100


# set verbosity to a not-allowed level.
# the user must set this value!
_verbosity_default = ERRLVL.INFNT + 1
verbosity = _verbosity_default

# generic wrapper for print()
def printmsg(msg="", errlvl=ERRLVL.INFNT):
    global verbosity
    if verbosity < ERRLVL.CRIT or verbosity > ERRLVL.INFNT:
        raise ValueError("Your code must set verbosity to a level greater than %d and less than %d" % (ERRLVL.CRIT, _verbosity_default))
    elif errlvl not in ERRLVL:
        raise ValueError("Your code uses an undefined error level: %d" % errlvl)
    else:
        if ERRLVL.CRIT <= errlvl <= verbosity:
            if errlvl == ERRLVL.CRIT:
                msg = "CRITICAL: " + msg
            elif errlvl == ERRLVL.ERROR:
                msg = "ERROR:    " + msg
            elif errlvl == ERRLVL.WARN:
                msg = "WARNING:  " + msg
            elif errlvl == ERRLVL.INFO:
                msg = "INFO:     " + msg
            elif errlvl == ERRLVL.DEBUG:
                msg = "DEBUG:    " + msg
            else:
                msg = "UNKNOWN:  " + msg
            print(msg, file=sys.stderr)

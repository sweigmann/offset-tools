# flake8: noqa: E501
#
#   (C) Sebastian Weigmann, 2025
#   This software is released under:
#   GNU GENERAL PUBLIC LICENSE, Version 3
#   Please find the full text in LICENSE.
#
# generic imports
import os

# specific imports
from enum import IntEnum, StrEnum

# line endings for different OSes
LINESEP = {'unix': b'\n', 'windows': b'\r\n', 'macos': b'\r'}

# filepathname arg validators for argparse
def type_infile(fpathname):
    if fpathname == "stdin" or os.path.exists(os.path.abspath(fpathname)):
        return fpathname
    else:
        raise FileNotFoundError("'" + fpathname + "'")


def type_outfile(fpathname):
    if os.path.exists(os.path.abspath(fpathname)):
        raise FileExistsError("'" + fpathname + "'")
    else:
        return fpathname

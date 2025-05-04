# flake8: noqa: E501
#
#   (C) Sebastian Weigmann, 2025
#   This software is released under:
#   GNU GENERAL PUBLIC LICENSE, Version 3
#   Please find the full text in LICENSE.
#
# generic imports
import typing
import os
import argparse

# specific imports
try:
    from common import mytypes as T
except ModuleNotFoundError:
    from offset_tools.common import mytypes as T

# common parsing module for all offset tools
# to be included by CLI programs line this:
# parser = argparse.ArgumentParser(parents=[blockline.parser])
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--before", "-B", type=int, default=0, metavar="NUM", help="print NUM units before matching block/line")
parser.add_argument("--after", "-A", type=int, default=0, metavar="NUM", help="print NUM units after matching block/line")
parser.add_argument("--blocksize", "-s", type=int, default=512, metavar="BS", help="block size for block mode, buffer size for line mode (default: %(default)d)")
parser.add_argument("--linesep", "-d", choices=["unix", "windows", "macos"], default="unix", help="line endings for a text file to dump lines from (default: %(default)s)")
parser.add_argument("datatype", choices=["lines", "blocks"], metavar="datatype", help="state if input is parsed as lines or blocks (choices: %(choices)s)")


class BlockLine(object):
    def __init__(self, args):
        self.args = args
        self.bufsize = args.blocksize
        self.linesep = T.LINESEP.get(args.linesep)

    def __reverse_find(self, filehandle: typing.BinaryIO, position: int, substring: bytes) -> int:
        p = position
        f = filehandle
        s = substring
        idx = 0
        while True:
            sz = min(self.bufsize, p)
            p -= sz
            f.seek(p)
            buf = f.read(sz)
            try:
                idx = buf.rindex(s) + p
                f.seek(idx)
                break
            except ValueError:
                pass
            if p == 0:
                break
        f.seek(position)
        return idx

    def __forward_find(self, filehandle: typing.BinaryIO, position: int, substring: bytes) -> int:
        p = position
        f = filehandle
        s = substring
        idx = 0
        f.seek(0, os.SEEK_END)
        idx_max = f.tell()
        while True:
            sz = min(self.bufsize, idx_max - p)
            f.seek(p)
            buf = f.read(sz)
            try:
                idx = buf.index(s) + p
                break
            except ValueError:
                p += sz
            if p >= idx_max:
                break
        return idx

    def dump_line(self, filehandle: typing.BinaryIO, position: int, substring: bytes) -> bytes:
        p = position
        f = filehandle
        s = substring
        b = self.args.before
        a = self.args.after
        idx_linestart = self.__reverse_find(f, p, s)
        while b > 0:
            idx_linestart = self.__reverse_find(f, idx_linestart - 1, s)
            b -= 1
        f.seek(p)
        idx_lineend = self.__forward_find(f, p, s)
        while a > 0:
            idx_lineend = self.__forward_find(f, idx_lineend + 1, s)
            a -= 1
        f.seek(idx_linestart + len(s))
        line = f.read(idx_lineend - idx_linestart)
        return line

    def dump_block(self, filehandle: typing.BinaryIO, position: int) -> bytes:
        p = position
        f = filehandle
        b = self.args.before
        a = self.args.after
        idx_blockstart = ((p // self.bufsize) * self.bufsize) - (b * self.bufsize)
        f.seek(idx_blockstart)
        bytes_to_read = self.bufsize + (b * self.bufsize) + (a * self.bufsize)
        block = f.read(bytes_to_read)
        return block

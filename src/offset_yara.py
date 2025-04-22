# flake8: noqa: E501
# This is offset-yara for getting lines or storage blocks by yara offsets.
#   (C) Sebastian Weigmann, 2025
#   This software is released under:
#   GNU GENERAL PUBLIC LICENSE, Version 3
#   Please find the full text in LICENSE.
#
# Exit codes:
#   0:  all good
#   1:  generic error
#   2:  argument parser error
#
#
# generic imports
import argparse
import os.path
import sys
import re
import hashlib

# specific imports
#from enum import IntEnum, StrEnum
from common import errors as ERR
from common import mytypes as T
from common import blockline
from common import version

# 3rd-party imports
# none yet

# global variables
oy_progname = "offset_yara"
oy_progver = "2"
progname = oy_progname + " (" + version.progname + ")"
progver = version.progver + "-" + oy_progver
ERR.verbosity = 0


def parse_args():
    global progname
    global progver
    parser = argparse.ArgumentParser(
        prog=progname,
        description="Get lines or blocks by offset",
        epilog="Note: This tool cannot extract content from multiple files in one run. All offsets given in --yarafile FILE must originate from the same input file!",
        parents=[blockline.parser]
    )
    parser.add_argument(
        "--yarafile",
        type=T.type_infile,
        default="stdin",
        metavar="FILE",
        help="source of YARA output (default: %(default)s)"
    )
    parser.add_argument(
        "--nodupes",
        "-u",
        action="store_true",
        help="results are given for the smallest offset only, all duplicates are omitted"
    )
    parser.add_argument(
        "--infile",
        "-i",
        type=T.type_infile,
        default=None,
        metavar="FILE",
        help="file or image to extract lines or blocks from"
    )
    parser.add_argument(
        "--outdir",
        "-o",
        type=T.type_outfile,
        default="stdout",
        metavar="DIR",
        help="write one file per offset to DIR (default: %(default)s)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="can be given multiple times to increase verbosity",
    )
    parser.add_argument("--version", action="version", version="%(prog)s v" + progver)
    try:
        args = parser.parse_args()
        return args
    except Exception as excpt:
        # we get here when anything is wrong with provided arguments. fail and exit.
        ERR.printmsg(f"{type(excpt).__name__}: {excpt}", ERR.ERRLVL.CRIT)
        sys.exit(ERR.EXIT.ARGPARSE)



def get_offsets(yaraout: list) -> list:
    offsets = []
    regex = r'^(0x[0-9a-f]+)'
    # user_yes yes.txt          --> None
    # 0x14e:$user_yes01: yes    --> 0x14e
    # 0x213:$user_yes01: yes    --> 0x213
    rec = re.compile(regex)
    for line in yaraout:
        if type(line) is bytes:
            line = line.decode('utf-8')
        regex_group = rec.match(line)
        if regex_group:
            hex_offset = regex_group.group()
            dec_offset = int(hex_offset, 16)
            offsets.append(dec_offset)
    sorted_uniq_offsets = sorted(set(offsets))
    return sorted_uniq_offsets


def __main():
    global progname
    global progver
    ERR.verbosity = ERR.ERRLVL.DEBUG
    ERR.printmsg("TEST", ERR.ERRLVL.INFNT)
    args = parse_args()
    hashes = []
    # read YARA output file and get offsets...
    list_offsets = []
    if args.yarafile == "stdin":
        list_offsets = get_offsets(sys.stdin.readlines())
    else:
        with open(args.yarafile, "rb") as f:
            list_offsets = get_offsets(f.readlines())
    assert(type(list_offsets) is list)
    bl = blockline.BlockLine(args)
    with open(args.infile, "rb") as ifile:
        for p in list_offsets:
            # get buffer
            if args.datatype == "lines":
                buf = bl.dump_line(ifile, p, T.LINESEP.get(args.linesep))
            elif args.datatype == "blocks":
                buf = bl.dump_block(ifile, p)
            else:
                ERR.printmsg("Neither blocks nor lines, what shall I do? Bailing out!", ERR.ERRLVL.CRIT)
                raise ValueError(f"Undefined datatype: {args.datatype}")
            # dup removal before further processing
            # this is heavy on the cpu
            if args.nodupes:
                h = hashlib.sha256()
                h.update(buf)
                if h.hexdigest() in hashes:
                    # we already collected this hash
                    # we break this iteration and go on with the next one
                    continue
                else:
                    hashes.append(h.hexdigest())
            # go on with output
            if args.outdir == "stdout":
                sys.stdout.buffer.write(buf)
            else:
                if not os.path.exists(args.outdir):
                    os.makedirs(args.outdir)
                opfname = os.path.join(args.outdir, f"line_{hex(p)}.txt" if args.datatype == "lines" else f"block_{hex(p)}.bin")
                with open(opfname, "wb") as ofile:
                    ofile.write(buf)
    return


def main():
    try:
        __main()
    except Exception as main_excpt:
        # yeah, this is truly unexpected. ever got CTRL+C'ed?? bail the heck out!
        ERR.printmsg(f"{type(main_excpt).__name__}: {main_excpt}", ERR.ERRLVL.CRIT)
        sys.stderr.flush()
        sys.stdout.flush()
        sys.exit(ERR.EXIT.GENERIC)
    sys.exit(ERR.EXIT.OK)


# void main() { do stuff }
if __name__ == "__main__":
    main()

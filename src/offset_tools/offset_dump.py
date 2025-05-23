# flake8: noqa: E501
# This is offset_dump for getting lines or storage blocks by yara or strings offsets.
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
import os
import sys
import re
import hashlib

# specific imports
# from enum import IntEnum, StrEnum
try:
    from common import errors as ERR
    from common import mytypes as T
    from common import version
    from common import blockline
except ModuleNotFoundError:
    from offset_tools.common import errors as ERR
    from offset_tools.common import mytypes as T
    from offset_tools.common import version
    from offset_tools.common import blockline


# 3rd-party imports
# none yet

# global variables
my_progname = "offset_dump"
my_progver = "2"
progname = my_progname + " (" + version.progname + ")"
progver = version.progver + "-" + my_progver
ERR.verbosity = 0


def parse_args() -> argparse.Namespace:
    global progname
    global progver
    parser = argparse.ArgumentParser(
        prog=my_progname,
        description="Get lines or blocks by yara or strings offset",
        epilog="Note: This tool cannot extract content from multiple files in one run. All offsets given in --offsetfile FILE must originate from the same input!",
    )
    parser.add_argument("--version", action="version", version=progname + " v" + progver)
    parser_common = argparse.ArgumentParser(add_help=False)
    parser_common.add_argument(
        "--nodupes",
        "-u",
        action="store_true",
        help="results are given for the smallest offset only, all duplicates are omitted",
    )
    parser_common.add_argument(
        "--offsetfile",
        "-f",
        type=T.type_infile,
        default="stdin",
        metavar="FILE",
        help="source of offsets (default: %(default)s)",
    )
    parser_common.add_argument(
        "--infile",
        "-i",
        type=T.type_infile,
        default=None,
        metavar="FILE",
        help="file or image to extract lines or blocks from",
    )
    parser_common.add_argument(
        "--outdir",
        "-o",
        type=T.type_outfile,
        default="stdout",
        metavar="DIR",
        help="write one file per offset to DIR (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(title="process offsets from", dest="method", metavar="offset_method")
    subparser_yara = subparsers.add_parser('yara', help='use offsets from yara output', parents=[parser_common, blockline.parser])
    subparser_strings = subparsers.add_parser('strings', help='use offsets from strings output', parents=[parser_common, blockline.parser])
    subparser_strings.add_argument(
        "--type",
        "-t",
        choices=["dec", "hex"],
        default="dec",
        help="offset format in STRINGS file (default: %(default)s)",
    )
    try:
        args = parser.parse_args()
#        print(f"args: {args}", file=sys.stderr)
        return args
    except Exception as excpt:
        # we get here when anything is wrong with provided arguments. fail and exit.
        ERR.printmsg(f"{type(excpt).__name__}: {excpt}", ERR.ERRLVL.CRIT)
        sys.exit(ERR.EXIT.ARGPARSE)


def get_offsets(input: list, offsetmethod: str, offsettype: str | None = None) -> list:
    offsets: list[int] = []
    base = 10 if offsettype == "dec" else 16
    regex = r"^(0x[0-9a-f]+)" if offsetmethod == "yara" else r"^ *([0-9a-f]+) "
    # YARA:
    # user_yes yes.txt          --> None
    # 0x14e:$user_yes01: yes    --> 0x14e
    # 0x213:$user_yes01: yes    --> 0x213
    # STRINGS:
    #     122 dirty bit         --> 122
    # 21691669 WXDP             --> 21691669
    #      7a dirty bit         --> 7a
    # 14afd15 WXDP              --> 14afd15
    rec = re.compile(regex)
    for line in input:
        if type(line) is bytes:
            line = line.decode("utf-8")
        regex_group = rec.match(line)
        if regex_group:
            offset_str: str = regex_group.group().strip()
            offset_int: int = int(offset_str, base)
            offsets.append(offset_int)
    sorted_uniq_offsets = sorted(set(offsets))
    return sorted_uniq_offsets


def __main() -> None:
    global progname
    global progver
    ERR.verbosity = ERR.ERRLVL.DEBUG
    args = parse_args()
    hashes = []
    # read YARA or STRINGS output file and get offsets...
    list_offsets = []
    if args.offsetfile == "stdin":
        list_offsets = get_offsets(sys.stdin.readlines(), args.method, "hex" if args.method == "yara" else args.type)
    else:
        with open(args.offsetfile, "rb") as f:
            list_offsets = get_offsets(f.readlines(), args.method, "hex" if args.method == "yara" else args.type)
    assert type(list_offsets) is list
    bl = blockline.BlockLine(args)
    with open(args.infile, "rb") as ifile:
        for p in list_offsets:
            # get buffer
            if args.datatype == "lines":
                buf = bl.dump_line(ifile, p, T.LINESEP.get(args.linesep))
            elif args.datatype == "blocks":
                buf = bl.dump_block(ifile, p)
            else:
                ERR.printmsg(
                    "Neither blocks nor lines, what shall I do? Bailing out!",
                    ERR.ERRLVL.CRIT,
                )
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
                if args.method == "strings":
                    fmt_p = hex(p) if args.type == "hex" else p
                else:
                    fmt_p = hex(p)
                opfname = os.path.join(
                    args.outdir,
                    (
                        f"line_{fmt_p}.txt"
                        if args.datatype == "lines"
                        else f"block_{fmt_p}.bin"
                    ),
                )
                with open(opfname, "wb") as ofile:
                    ofile.write(buf)
    return


def main() -> None:
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

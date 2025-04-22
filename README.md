# offset-tools

Tool collection to extract lines from files or blocks from images 
based on an offset.

<img src="https://github.com/sweigmann/offset-tools/actions/workflows/codeql-analysis.yml/badge.svg?branch=main">
<img src="https://github.com/sweigmann/offset-tools/actions/workflows/python-linux.yml/badge.svg?branch=main">
<img src="https://github.com/sweigmann/offset-tools/actions/workflows/debian.yml/badge.svg?branch=main">
<img src="https://github.com/sweigmann/offset-tools/actions/workflows/ubuntu.yml/badge.svg?branch=main">

## installation:

```bash
pipx install git+https://codeberg.org/DFIR/offset-tools.git
```

## usage:

### offset-yara:

While `yara` matches rules to files, it usually does not provide 
more context than an offset and a rule name. Thus, running `yara` on 
very large log files or on device nodes or image files would yield
insufficient data, where a full line from the log or an inode block is 
desired. 

`offset-yara` was made to pull full lines from text files. It can also 
pull complete raw blocks from device nodes or image files. All output
is either dumped to `stdout` so it can be directly piped into another 
tool, or it is stored in separate files within an output directory. 
Each file in that directory will hold the data carved from around one 
of the offsets provided. Duplicates such as multiple hits per line 
can be avoided on request. Similar to `grep`, there are also options 
to extract more lines or blocks before and after the data object 
which was referenced by the offset.

#### example:

Let's have a look at this rule which will match the strings "yes" 
and "/home/yes".

```yara
rule find_yes {
    strings:
        $yes01 = "yes" fullword nocase ascii wide 
        $yes02 = "yes" base64 base64wide
        $yes03 = "Yes" base64 base64wide
        $yes04 = "YES" base64 base64wide
    condition:
        any of them
}
```

Running `yara` with this rule against a file `yes.txt` which you 
may find in the test directory would yield the output:

```plain
find_yes test/yes.txt
0x14e:$yes01: yes
0x213:$yes01: yes
```

To get the lines referenced by the hexadecimal offsets, you might run:

```bash
$ offset-yara lines --yarafile test/yara-out_yes.txt --infile test/yes.txt 
To generate text with the word "yes", you can use various creative methods. 
express "yes" in English, such as "yep", "sure", or "totally", which can 
```

If small blocks, i.e. 16 bytes per block, sould be carved out instead, 
this command would do it:

```bash
$ offset-yara blocks --yarafile test/yara-out_yes.txt --infile test/yes.txt --outdir blocks --blocksize 16
$ ls -l blocks/
total 8
-rw-rw-r-- 1 user user  16 Apr 29 22:11 block_0x14e.bin
-rw-rw-r-- 1 user user  16 Apr 29 22:11 block_0x213.bin
$ cat blocks/block_0x213.bin 
s "yes" in Engli
```

The equivalent `dd` command would go like this:

```bash
$ dd if=test/yes.txt skip=$((0x213 / 16)) bs=16 count=1
s "yes" in Engli1+0 records in
1+0 records out
16 bytes copied, 4,5118e-05 s, 355 kB/s
```

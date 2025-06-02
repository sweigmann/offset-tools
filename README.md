# offset-tools

Tool collection to extract lines from files or blocks from images based
on an offset. Offsets can be provided as output from `yara` or `strings`.

<img src="https://github.com/sweigmann/offset-tools/actions/workflows/codeql-analysis.yml/badge.svg?branch=main">
<img src="https://github.com/sweigmann/offset-tools/actions/workflows/python-linux.yml/badge.svg?branch=main">
<img src="https://github.com/sweigmann/offset-tools/actions/workflows/debian.yml/badge.svg?branch=main">
<img src="https://github.com/sweigmann/offset-tools/actions/workflows/ubuntu.yml/badge.svg?branch=main">
<img src="https://img.shields.io/github/downloads/sweigmann/offset-tools/total">

## installation:

```bash
pipx install git+https://codeberg.org/DFIR/offset-tools.git
```

## usage:

### offset_dump:

While `yara` matches rules to files, it usually does not provide 
more context than an offset and a rule name. Thus, running `yara` on 
very large log files or on device nodes or image files would yield
insufficient data, where a full line from the log or an inode block is 
desired. The same would be true for `strings` if it was run with
the `-t` option.

`offset_dump` was made to pull full lines from text files as well as
complete raw blocks from device nodes or image files. It may be given
output from `yara` or from `strings -t (d|x)` as offset input along
with the file data should be dumped from.

All output is either dumped to `stdout` so it can be directly piped
into another tool, or it is stored in separate files within an output
directory. Each file in that directory will hold the data carved from
around one of the offsets provided. Duplicates such as multiple hits
per line can be avoided on request. Similar to `grep`, there are also
options to extract more lines or blocks before and after the data object 
which was referenced by the offset.

#### examples:

##### yara:

Let's have a look at this `yara` rule which will match the string "yes"
case insensitively.

```yara
rule find_yes {
    strings:
        $yes01 = "yes" fullword nocase ascii wide 
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
$ offset_dump yara lines --offsetfile test/yara-out_yes.txt --infile test/yes.txt 
To generate text with the word "yes", you can use various creative methods. 
express "yes" in English, such as "yep", "sure", or "totally", which can 
```

If small blocks should be carved out instead (i.e. 16 bytes per block), 
this command would do it:

```bash
$ offset_dump yara blocks --offsetfile test/yara-out_yes.txt --infile test/yes.txt --outdir blocks --blocksize 16
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

##### strings:

Running `strings` in conjunction with `grep` may yield reasonable results
as well if `yara` is not an option. Remember to pass the option `-t` to
`strings` and select either `d` for offsets in decimal or `x` for hexadecimal.
Then `grep` the output for the values you want to keep. The result is suitable
as input for `offset_dump`. 

Using `strings` to find all occurrences of case-insensitive "yes"es on
a small disk image would look like this:

```bash
$ strings --all -t x test/cirros-0.6.3-x86_64.qcow2 | grep -i yes
  575b4 xYes (
 7d23b2 :YEs-
 c51eee [{%YEs
 d36c76 I#Yes	
1053f01 yesB
11a2a80 YEsOW
11e0418 dYes
1240e37 &=YES
1347880 ]oYes
```

This can directly serve as input for `offset_dump`:

```bash
$ strings --all -t x test/cirros-0.6.3-x86_64.qcow2 | grep -i yes | offset_dump strings blocks --type hex --infile test/cirros-0.6.3-x86_64.qcow2 --outdir blocks --blocksize 64
$ ls -l blocks/
total 36
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0x1053f01.bin
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0x11a2a80.bin
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0x11e0418.bin
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0x1240e37.bin
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0x1347880.bin
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0x575b4.bin
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0x7d23b2.bin
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0xc51eee.bin
-rw-rw-r-- 1 user user  64 May  4 22:06 block_0xd36c76.bin
```

Remember to choose a reasonably large blocksize as `strings` will index not 
the occurrence of your `grep`ped value, but the beginning of the actual string
within the scanned file. Choosing a blocksize too small may yield output which
does not include your desired substring.

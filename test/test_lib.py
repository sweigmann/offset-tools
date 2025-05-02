#!/usr/bin/env python3
# flake8: noqa: E501
import pytest      # noqa: F401
import subprocess
import os
import shutil


class Test_offset_yara(object):
    # end-to-end tests
    def test_process(self):
        p = subprocess.run(
            ["python3", os.path.join("src", "offset_tools", "offset_yara.py"), "--help"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        assert p.returncode == 0
        assert "usage: offset_yara (offset-tools) [-h] " in p.stdout

    def test_lines(self):
        p = subprocess.run(
            ["python3", os.path.join("src", "offset_tools", "offset_yara.py"), "lines", "--yarafile", os.path.join("test", "yara-out_yes.txt"), "--infile", os.path.join("test", "yes.txt")],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        assert p.returncode == 0
        assert 'To generate text with the word "yes", you can use various creative methods.' in p.stdout
        assert 'express "yes" in English, such as "yep", "sure", or "totally", which can' in p.stdout

    def test_blocks(self):
        if (os.path.exists("blocks") and os.path.isdir("blocks")):
            shutil.rmtree("blocks")
        p = subprocess.run(["python3", os.path.join("src", "offset_tools", "offset_yara.py"), "blocks", "--yarafile", os.path.join("test", "yara-out_qcow.txt"), "--infile", os.path.join("test", "cirros-0.6.3-x86_64.qcow2"), "--outdir", "blocks", "--blocksize", "32", "--nodupes"],
            capture_output=True,
            text=False,
            check=True,
            timeout=10,
        )
        assert p.returncode == 0
        assert os.path.exists("blocks")
        assert os.path.isdir("blocks")
        assert os.path.isfile(os.path.join("blocks", "block_0xfcacd7.bin"))
        assert os.path.isfile(os.path.join("blocks", "block_0x102897c.bin"))
        assert os.path.isfile(os.path.join("blocks", "block_0xf26600.bin"))
        with open(os.path.join("blocks", "block_0xfcacd7.bin"), 'rb') as f:
            assert b'\x07\x1cN|f\xab\xe9\xdd\x97\xbc\x08\xda\x0eE\xd2\xb3\x19\x85$\x18c\xf4\x1byes\xcbi\x95-)\xfc' in f.read()
        with open(os.path.join("blocks", "block_0x102897c.bin"), 'rb') as f:
            assert b'\x988u\xa8\x1d\x97A\xd8}\x86\x97+\x13\xdf\x87\xdb\xf5LF\xaf\xeb\xdfND\xc2\xf0m\x18yes\x06' in f.read()
        with open(os.path.join("blocks", "block_0xf26600.bin"), 'rb') as f:
            assert b'yES\xb7\xf8\x9b\x1b\xbd\xb4\xf56\xf1\x93\xc9\x13H\xb5\xfbf\xb1\x07w\xe1\xe9\xb4\x05Z\xbc1\x85\x0fY' in f.read()
        shutil.rmtree("blocks")

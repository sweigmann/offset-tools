#!/usr/bin/env python3
# flake8: noqa: E501
import pytest      # noqa: F401
import subprocess
import os
import shutil


class Test_offset_dump(object):
    # end-to-end tests
    def test_process(self):
        p = subprocess.run(
            ["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "--help"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        assert p.returncode == 0
        assert "usage: offset_dump [-h] " in p.stdout

    def test_process_yara(self):
        p = subprocess.run(
            ["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "yara", "--help"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        assert p.returncode == 0
        assert "usage: offset_dump yara [-h] " in p.stdout

    def test_process_strings(self):
        p = subprocess.run(
            ["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "strings", "--help"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        assert p.returncode == 0
        assert "usage: offset_dump strings [-h] " in p.stdout

    def test_yara_lines(self):
        p = subprocess.run(
            ["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "yara", "lines", "--offsetfile", os.path.join("test", "yara-out_yes.txt"), "--infile", os.path.join("test", "yes.txt")],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        assert p.returncode == 0
        assert 'To generate text with the word "yes", you can use various creative methods.' in p.stdout
        assert 'express "yes" in English, such as "yep", "sure", or "totally", which can' in p.stdout

    def test_yara_blocks(self):
        if (os.path.exists("blocks") and os.path.isdir("blocks")):
            shutil.rmtree("blocks")
        p = subprocess.run(["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "yara", "blocks", "--offsetfile", os.path.join("test", "yara-out_qcow.txt"), "--infile", os.path.join("test", "cirros-0.6.3-x86_64.qcow2"), "--outdir", "blocks", "--blocksize", "32", "--nodupes"],
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

    def test_strings_lines_hex(self):
        p = subprocess.run(
            ["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "strings", "lines", "--type", "hex", "--offsetfile", os.path.join("test", "strings-hex-ascii-all_yes.txt"), "--infile", os.path.join("test", "yes.txt")],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        assert p.returncode == 0
        assert 'To generate text with the word "yes", you can use various creative methods.' in p.stdout
        assert 'express "yes" in English, such as "yep", "sure", or "totally", which can' in p.stdout

    def test_strings_blocks_hex(self):
        if (os.path.exists("blocks") and os.path.isdir("blocks")):
            shutil.rmtree("blocks")
        p = subprocess.run(["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "strings", "blocks", "--type", "hex", "--offsetfile", os.path.join("test", "strings-hex-ascii-all_qcow_partial.txt"), "--infile", os.path.join("test", "cirros-0.6.3-x86_64.qcow2"), "--outdir", "blocks", "--blocksize", "32", "--nodupes"],
            capture_output=True,
            text=False,
            check=True,
            timeout=10,
        )
        assert p.returncode == 0
        assert os.path.exists("blocks")
        assert os.path.isdir("blocks")
        assert os.path.isfile(os.path.join("blocks", "block_0x1053f01.bin"))    # 17121025
        assert os.path.isfile(os.path.join("blocks", "block_0x11a2a80.bin"))    # 18492032
        assert os.path.isfile(os.path.join("blocks", "block_0x1347880.bin"))    # 20215936
        with open(os.path.join("blocks", "block_0x1053f01.bin"), 'rb') as f:
            assert b'\xd5yesB\xacA\x88\x8fk=\x00\xfc\x8d\xc9~\x0f\xcc\xab!\x07f\xd27\xeaw\x9b\xe5\x7f ^\xf5' in f.read()
        with open(os.path.join("blocks", "block_0x11a2a80.bin"), 'rb') as f:
            assert b'YEsOW\xf5\xc2]\xe2i\xa9*\x16v\ra.Mo\xe1H\xb4%q\xd7I\xa4\x8a\xe4\x89\xbd\xdd' in f.read()
        with open(os.path.join("blocks", "block_0x1347880.bin"), 'rb') as f:
            assert b']oYes\xe5YP9\r\xa0h\x12^B\xa5\xff\xde~\xc5\xb2z@\xc7\xbc7Ox\x9a\xba^\x99' in f.read()
        shutil.rmtree("blocks")

    def test_strings_lines_dec(self):
        p = subprocess.run(
            ["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "strings", "lines", "--type", "dec", "--offsetfile", os.path.join("test", "strings-dec-ascii-all_yes.txt"), "--infile", os.path.join("test", "yes.txt")],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        assert p.returncode == 0
        assert 'To generate text with the word "yes", you can use various creative methods.' in p.stdout
        assert 'express "yes" in English, such as "yep", "sure", or "totally", which can' in p.stdout

    def test_strings_blocks_dec(self):
        if (os.path.exists("blocks") and os.path.isdir("blocks")):
            shutil.rmtree("blocks")
        p = subprocess.run(["python3", os.path.join("src", "offset_tools", "offset_dump.py"), "strings", "blocks", "--type", "dec", "--offsetfile", os.path.join("test", "strings-dec-ascii-all_qcow_partial.txt"), "--infile", os.path.join("test", "cirros-0.6.3-x86_64.qcow2"), "--outdir", "blocks", "--blocksize", "32", "--nodupes"],
            capture_output=True,
            text=False,
            check=True,
            timeout=10,
        )
        assert p.returncode == 0
        assert os.path.exists("blocks")
        assert os.path.isdir("blocks")
        assert os.path.isfile(os.path.join("blocks", "block_17121025.bin"))    # 0x1053f01
        assert os.path.isfile(os.path.join("blocks", "block_18492032.bin"))    # 0x11a2a80
        assert os.path.isfile(os.path.join("blocks", "block_20215936.bin"))    # 0x1347880
        with open(os.path.join("blocks", "block_17121025.bin"), 'rb') as f:
            assert b'\xd5yesB\xacA\x88\x8fk=\x00\xfc\x8d\xc9~\x0f\xcc\xab!\x07f\xd27\xeaw\x9b\xe5\x7f ^\xf5' in f.read()
        with open(os.path.join("blocks", "block_18492032.bin"), 'rb') as f:
            assert b'YEsOW\xf5\xc2]\xe2i\xa9*\x16v\ra.Mo\xe1H\xb4%q\xd7I\xa4\x8a\xe4\x89\xbd\xdd' in f.read()
        with open(os.path.join("blocks", "block_20215936.bin"), 'rb') as f:
            assert b']oYes\xe5YP9\r\xa0h\x12^B\xa5\xff\xde~\xc5\xb2z@\xc7\xbc7Ox\x9a\xba^\x99' in f.read()
        shutil.rmtree("blocks")

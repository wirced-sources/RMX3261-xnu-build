"""Validate the negative exec asset before embedding it into authenticated data.

Synthetic Mach-O inputs below test the auditor, not execution or linking.
"""
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from qemu_user_fixture import audit


def fixture():
    data=bytearray(512)
    struct.pack_into('<8I',data,0,0xfeedfacf,0x100000c,0,2,2,360,0,0)
    struct.pack_into('<II16s4Q4I',data,32,0x19,72,b'__TEXT',0x100000000,512,0,512,5,5,0,0)
    struct.pack_into('<4I',data,104,5,288,6,68)
    struct.pack_into('<Q',data,376,0x100000000+400)
    struct.pack_into('<I',data,400,0xd420a2a0)
    return data


class UnsignedFixtureTests(unittest.TestCase):
    def test_owned_unsigned_trap_entry(self):
        proof=audit(fixture())
        self.assertTrue(proof['unsigned'] and proof['entry_is_trap'])
        self.assertFalse(proof['apple_userland'])

    def test_reject_wrong_arch_entry_protection_signature(self):
        for offset,value,fmt in ((4,0x1000007,'I'),(16,3,'I'),(20,0xffffffff,'I'),
                (92,7,'I'),(376,0x100001000,'Q'),(400,0xd503201f,'I'),(104,0x1d,'I'),
                (116,67,'I'),(80,513,'Q'),(108,280,'I')):
            with self.subTest(offset=offset,value=value):
                data=fixture(); struct.pack_into('<'+fmt,data,offset,value)
                with self.assertRaises(ValueError): audit(data)
        for length in (0,31,32,392,401):
            with self.subTest(length=length):
                with self.assertRaises(ValueError): audit(fixture()[:length])


if __name__=='__main__': unittest.main()

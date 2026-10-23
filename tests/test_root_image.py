"""Malformed host image inputs must never be embedded as trusted root media."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from xnu_storage import validate_image


def headers():
    # Synthetic header/extent fixture, not a mountable filesystem claim.
    data=bytearray(32*4096)
    data[1024:1028]=b'H+\0\4'
    struct.pack_into('>I',data,1028,1<<8)
    struct.pack_into('>III',data,1064,4096,32,20)
    for block,offset in enumerate((112,192,272),1):
        struct.pack_into('>QII',data,1024+offset,4096,4096,1)
        struct.pack_into('>II',data,1024+offset+16,block,1)
    data[-1024:-512]=data[1024:1536]
    return data


class RootImageTests(unittest.TestCase):
    def test_geometry_and_required_extents(self):
        self.assertEqual(validate_image(headers())['allocation_blocks'],32)

    def test_reject_bad_formats_and_geometry(self):
        for offset,value in ((1024,b'NXSB'),(1064,struct.pack('>I',513)),
                             (1068,struct.pack('>I',0xffffffff)),(1072,struct.pack('>I',33)),
                             (1028,struct.pack('>I',0)),(1028,struct.pack('>I',(1<<8)|(1<<14))),
                             (1028,struct.pack('>I',(1<<8)|(1<<30))),
                             (len(headers())-1024,b'BAD!')):
            with self.subTest(offset=offset,value=value):
                data=headers(); data[offset:offset+len(value)]=value
                with self.assertRaises(ValueError): validate_image(data)

    def test_reject_truncation_and_invalid_metadata(self):
        for n in (0,511,1024,4096,len(headers())-512):
            with self.subTest(length=n):
                with self.assertRaises(ValueError): validate_image(headers()[:n])
        for offset,value in ((1024+112+4,0),(1024+112+16,31),(1024+192+16,1)):
            data=headers(); struct.pack_into('>I',data,offset,value)
            with self.assertRaises(ValueError): validate_image(data)


if __name__=='__main__': unittest.main()

import re
import os
import glob
import subprocess
from collections import OrderedDict
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

product_dict = OrderedDict()
adr_dict = OrderedDict()
process_dict = OrderedDict()


def hex_to_dec(hex_string):
    dec_string = ""
    hex_range = [6, 4, 2, 0]
    for index in hex_range:
        dec_string += hex_string[index:index + 2]
    print(dec_string)


m = hashlib.md5()
m.update(r'my_process.exe******************'.encode('utf-8'))

hex_digest = m.hexdigest()

print(hex_digest)

hex_digest_01 = hex_digest[0:8]
hex_digest_02 = hex_digest[8:16]
hex_digest_03 = hex_digest[16:24]
hex_digest_04 = hex_digest[24:32]

hex_to_dec(hex_digest_01)
hex_to_dec(hex_digest_02)
hex_to_dec(hex_digest_03)
hex_to_dec(hex_digest_04)

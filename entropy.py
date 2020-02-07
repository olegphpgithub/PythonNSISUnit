#!/usr/bin/env python

import argparse
import os

import pefile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser()
parser.add_argument('--pe-file', required=True)
args = parser.parse_args()

pe = pefile.PE(args.pe_file, fast_load=True)

for section in pe.sections:
    high_entropy = ' '
    section_name = section.Name.rstrip(b'\x00').decode()
    section_entropy = section.get_entropy()
    if section_entropy > 6.8:
        high_entropy = '!'
    print(f'[{high_entropy}] Name: {section_name:<9} Entropy: {section_entropy:.2f} (Min=0.0, Max=8.0)')

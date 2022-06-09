#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import glob
from os import path
from os import listdir
from os.path import isfile, join
import string
from random import randint

BASE_DIR = path.dirname(path.abspath(__file__))
TARGET_PATH = path.join(BASE_DIR, r"MultyHash")
EDATA_EXE = path.join(BASE_DIR, r"nsis308.dat")

def get_files():
  onlyfiles = [f for f in listdir(TARGET_PATH) if isfile(join(TARGET_PATH, f))]
  for file_path in glob.glob(TARGET_PATH + os.sep + r'*.exe'):
    with open(file_path, 'ab') as outfile:
      with open(EDATA_EXE, 'rb') as edata_file:
        outfile.write(edata_file.read())

get_files()
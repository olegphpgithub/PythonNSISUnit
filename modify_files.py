#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from os import path
import string
from random import randint
from os import listdir
from os.path import isfile, join


DIRECTORY = r"d:\Regular.Downloader\AutoCompile\PU"


def modify_files():
    source_files = [f for f in listdir(DIRECTORY) if isfile(join(DIRECTORY, f))]
    for file in source_files:
        source_file_path = r"%s\%s" % (DIRECTORY, file)
        source_was_found = False
        modified_lines = list()
        with open(source_file_path, 'rb') as source_file:
            content = source_file.readlines()
            for line in content:
                source_line = line.rstrip()
                m = re.search(r'(.*)CallInstDLL\s+\$PLUGINSDIR\\\$\{memorymodule\}.dll\s+/NOUNLOAD\s+\$\{CallDllProxy\}\s+\$\{(\w+)\}', source_line)
                if m is not None:
                    source_was_found = True
                    print(source_line)
                    print(m.group(2))
                    modified_line = r'%sCallInstDLL "$PLUGINSDIR\${memorymodule}.dll" /NOUNLOAD ${CallDllProxy}' % m.group(1)
                    modified_lines.append("%sPush ${%s}\n" % (m.group(1), m.group(2)))
                    modified_lines.append("%s\n" % modified_line)
                else:
                    modified_lines.append(line)
        if source_was_found:
            with open(source_file_path, 'wb') as target_file:
                for line in modified_lines:
                    target_file.write("%s" % line)


modify_files()

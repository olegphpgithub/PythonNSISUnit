import re
import os
import subprocess
from collections import OrderedDict


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILENAME = os.path.join(BASE_DIR, r"example.nsi")
COMPILERS_FILENAME = os.path.join(BASE_DIR, r"list.txt")
OUTPUT_DIRECTORY = os.path.join(BASE_DIR, r"output")


available_compressors = OrderedDict()
available_compressors[r'zlib'] = 'zlib'
available_compressors[r'bzip2'] = 'bzip2'
available_compressors[r'lzma'] = 'lzma'
available_compressors[r'/SOLID zlib'] = 'SOLID_zlib'
available_compressors[r'/SOLID bzip2'] = 'SOLID_bzip2'
available_compressors[r'/SOLID lzma'] = 'SOLID_lzma'


class CompilerList:
    def __init__(self, file_path):
        self.compiler_list = list()
        with open(file_path, "r") as input_file:
            input_lines = input_file.readlines()
            input_file.seek(0)
            for index, line in enumerate(input_lines):
                self.compiler_list.append(line.strip())


def compile_file(compiler_path, source_file):

    compiler_command = r'"%s" "%s"' % (compiler_path, source_file)

    try:
        device_null = open(os.devnull, 'wb')
        result = subprocess.Popen(compiler_command, stderr=device_null, shell=False)
        text = result.communicate()
        return_code = result.returncode

        if return_code != 0:
            print('Error: Could not compiled target file')
            exit(1)
        else:
            print(text)
            print('Target file was compiled successfully')

    except Exception as inst:
        print("EncryptFile: Error: An exception occurred while calling external program: %s" % str(inst))
        exit(1)


def change_compressor(source_file_path, compressor):

    compressor_statement = r'SetCompressor %s' % compressor

    with open(source_file_path, 'r+') as source_file:
        content_old = source_file.read()
        content_new = re.sub(r'SetCompressor.*', compressor_statement, content_old, flags=re.M)
        source_file.seek(0)
        source_file.write(content_new)


# compile_file(r'c:\Program Files (x86)\nsis-2.46.47.1\makensis.exe', r'c:\progs\nsislearn01\__argv.nsi')

for current_compressor in available_compressors.keys():
    change_compressor(SOURCE_FILENAME, current_compressor)


print("Hello, world!")

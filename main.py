import re
import os
import subprocess
from collections import OrderedDict


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILENAME = os.path.join(BASE_DIR, r"example.nsi")
COMPILED_FILENAME = os.path.join(BASE_DIR, r"example.exe")
COMPILERS_FILENAME = os.path.join(BASE_DIR, r"list.txt")
OUTPUT_DIRECTORY = os.path.join(BASE_DIR, r"output")


available_compilers = OrderedDict()


available_compressors = OrderedDict()
available_compressors[r'zlib'] = 'zlib'
available_compressors[r'bzip2'] = 'bzip2'
available_compressors[r'lzma'] = 'lzma'
available_compressors[r'SOLID_zlib'] = '/SOLID zlib'
available_compressors[r'SOLID_bzip2'] = '/SOLID bzip2'
available_compressors[r'SOLID_lzma'] = '/SOLID lzma'


def fill_compilers_dict(file_path):
    with open(file_path, "r") as input_file:
        input_lines = input_file.readlines()
        for index, line in enumerate(input_lines):
            compiler_index = line.strip().split(os.sep)[2]
            available_compilers[compiler_index] = line.strip().strip(r'"')


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

fill_compilers_dict(COMPILERS_FILENAME)

for current_compiler_key in available_compilers.keys():
    for current_compressor_key in available_compressors.keys():
        change_compressor(SOURCE_FILENAME, available_compressors[current_compressor_key])
        compile_file(available_compilers[current_compiler_key], SOURCE_FILENAME)
        target_filename = os.path.basename(COMPILED_FILENAME)
        target_filename = target_filename[:-4]
        target_filename = "%s%s%s.%s.%s.exe" % (OUTPUT_DIRECTORY,
                                                os.sep,
                                                target_filename,
                                                current_compiler_key,
                                                current_compressor_key)
        print(target_filename)
        os.rename(COMPILED_FILENAME, target_filename)


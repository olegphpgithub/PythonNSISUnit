import re
import os
import glob
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
        result = subprocess.Popen(compiler_command,
                                  stdout=subprocess.PIPE,
                                  stderr=device_null,
                                  shell=False)
        text = result.communicate()
        return_code = result.returncode

        if return_code != 0:
            print('Error: Could not compiled target file')
            print(text[0])
            exit(1)

    except Exception as ex:
        print("Error: An exception occurred while calling external program: %s: %s" % (compiler_command, str(ex)))
        exit(1)


def change_compressor(source_file_path, compressor):

    compressor_statement = r'SetCompressor %s' % compressor

    with open(source_file_path, 'r+') as source_file:
        content_old = source_file.read()
        content_new = re.sub(r'SetCompressor.*', compressor_statement, content_old, flags=re.M)
        source_file.seek(0)
        source_file.write(content_new)


"""
    Remove files in output directory
"""
fileList = glob.glob("%s%s%s" % (OUTPUT_DIRECTORY, os.sep, r'*.exe'))
for filePath in fileList:
    try:
        os.remove(filePath)
    except OSError:
        print("Error while deleting file : ", filePath)


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


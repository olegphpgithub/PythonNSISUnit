import re
import os
import glob
import subprocess
from collections import OrderedDict


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILENAME = os.path.join(BASE_DIR, r"example.nsi")
BUILD_OUTPUT_FILENAME = os.path.join(BASE_DIR, r"example.exe")
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
            available_compilers[compiler_index] = line.strip().strip(r'\'"')


def compile_file(compiler_path, source_file):

    if os.path.exists(BUILD_OUTPUT_FILENAME):
        os.remove(BUILD_OUTPUT_FILENAME)

    try:
        compiler_command = r'"%s" "%s"' % (compiler_path, source_file)

        device_null = open(os.devnull, r'wb')
        result = subprocess.Popen(compiler_command,
                                  stdout=subprocess.PIPE,
                                  stderr=device_null,
                                  shell=False)
        text = result.communicate()
        return_code = result.returncode

        if return_code != 0:
            print(r'Error: Could not compiled target file')
            print(text[0])
            exit(1)

    except Exception as cex:
        raise AssertionError(r'Error: An exception occurred while calling external program: %s: %s'
                             % (compiler_command, str(cex)))

    if not os.path.exists(BUILD_OUTPUT_FILENAME):
        raise AssertionError(r'Could not found output file "%s": Did you forget to specify output file in '
                             'BUILD_OUTPUT_FILENAME macro?' % BUILD_OUTPUT_FILENAME)


def change_compressor(source_file_path, compressor):

    compressor_statement = r'SetCompressor %s' % compressor

    with open(source_file_path, 'r+') as source_file:
        content_old = source_file.read()
        content_new = re.sub(r'SetCompressor.*', compressor_statement, content_old, flags=re.M)
        source_file.seek(0)
        source_file.truncate(0)
        source_file.write(content_new)


def clear_output_directory():
    """
        Remove files in output directory
    """
    if os.path.exists(OUTPUT_DIRECTORY):
        file_list = glob.glob(r'%s%s%s' % (OUTPUT_DIRECTORY, os.sep, r'*.exe'))
        for file_path in file_list:
            try:
                os.remove(file_path)
            except OSError:
                raise AssertionError(r'Could not clear output directory: Error while deleting file %s' % file_path)
    else:
        try:
            os.mkdir(OUTPUT_DIRECTORY)
        except OSError:
            raise AssertionError(r'Could not create output directory: "%s"' % OUTPUT_DIRECTORY)


try:
    clear_output_directory()
    fill_compilers_dict(COMPILERS_FILENAME)
    for current_compiler_key in available_compilers.keys():
        for current_compressor_key in available_compressors.keys():
            change_compressor(SOURCE_FILENAME, available_compressors[current_compressor_key])
            compile_file(available_compilers[current_compiler_key], SOURCE_FILENAME)
            build_target_filename = os.path.basename(BUILD_OUTPUT_FILENAME)
            build_target_filename = build_target_filename[:-4]
            build_target_filename = r'%s%s%s.%s.%s.exe' % (OUTPUT_DIRECTORY,
                                                           os.sep,
                                                           build_target_filename,
                                                           current_compiler_key,
                                                           current_compressor_key)
            print(build_target_filename)
            os.rename(BUILD_OUTPUT_FILENAME, build_target_filename)
    exit(0)
except BaseException as bex:
    print(bex)
    exit(1)

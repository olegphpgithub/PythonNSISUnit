import re
import os
import glob
import subprocess
from collections import OrderedDict


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_FILENAME = os.path.join(BASE_DIR, r"example.nsi")
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

    except Exception as ex:
        print(r'Error: An exception occurred while calling external program: %s: %s' % (compiler_command, str(ex)))
        exit(1)


def change_compressor(source_file_path, compressor):

    compressor_statement = r'SetCompressor %s' % compressor

    with open(source_file_path, 'r+') as source_file:
        content_old = source_file.read()
        content_new = re.sub(r'SetCompressor.*', compressor_statement, content_old, flags=re.M)
        source_file.seek(0)
        source_file.write(content_new)


def clear_output_directory():
    """
        Remove files in output directory
    """
    file_list = glob.glob(r'%s%s%s' % (OUTPUT_DIRECTORY, os.sep, r'*.exe'))
    for file_path in file_list:
        try:
            os.remove(file_path)
        except OSError:
            raise AssertionError(r'Could not clear output directory: Error while deleting file %s' % file_path)


def get_build_output_filename():
    print(SOURCE_FILENAME)
    with open(SOURCE_FILENAME, r'r+') as source_file:
        content_file = source_file.read()
        pattern = re.compile(r'OutFile\s+(.+)')
        match = pattern.search(content_file)
        if match:
            output_filename = match.group(1).strip(r'\'"')
            if os.path.isabs(output_filename):
                return output_filename
            else:
                return r'%s%s%s' % (os.path.dirname(SOURCE_FILENAME),
                                    os.sep,
                                    output_filename)
        else:
            raise AssertionError(r'Error: Invalid script: There is no "OutFile" command')


try:
    clear_output_directory()
    fill_compilers_dict(COMPILERS_FILENAME)
    build_output_filename = get_build_output_filename()
    for current_compiler_key in available_compilers.keys():
        for current_compressor_key in available_compressors.keys():
            change_compressor(SOURCE_FILENAME, available_compressors[current_compressor_key])
            compile_file(available_compilers[current_compiler_key], SOURCE_FILENAME)
            target_filename = os.path.basename(build_output_filename)
            target_filename = target_filename[:-4]
            target_filename = r'%s%s%s.%s.%s.exe' % (OUTPUT_DIRECTORY,
                                                     os.sep,
                                                     target_filename,
                                                     current_compiler_key,
                                                     current_compressor_key)
            print(target_filename)
            os.rename(build_output_filename, target_filename)
    exit(0)
except AssertionError as ex:
    print(ex.message)
    exit(1)


import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NSIS_INPUT_FILE = os.path.join(BASE_DIR, r"list.txt")
NSIS_OUTPUT_DIR = os.path.join(BASE_DIR, r"output")


class CompilerList:
    def __init__(self, file_path):
        self.compiler_list = list()
        with open(file_path, "r") as input_file:
            input_lines = input_file.readlines()
            input_file.seek(0)
            for index, line in enumerate(input_lines):
                self.compiler_list.append(line.strip())


def compile_file(compiler_path, source_path):

    compiler_command = r'"%s" "%s"' % (compiler_path, source_path)

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


compile_file(r'c:\Program Files (x86)\nsis-2.46.47.1\makensis.exe', r'c:\progs\nsislearn01\__argv.nsi')
print("Hello, world!")

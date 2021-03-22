import os, sys
import struct
import pefile
import tempfile
from pathlib import Path
import shutil


security_directory_address = 0
security_directory_size = 0
signature_size = 0
file_size_inf = 0
file_size_def = 0


def back_to_original(file_path):

    global security_directory_address, security_directory_size, signature_size, file_size_inf, file_size_def
    file_extension = Path(file_path).suffix
    file_size_inf = Path(file_path).stat().st_size
    if file_extension == r'.exe':
        pe = pefile.PE(file_path)
        for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if data_directory.name == r'IMAGE_DIRECTORY_ENTRY_SECURITY':
                security_directory_address = data_directory.VirtualAddress
                security_directory_size = data_directory.Size
        pe.close()

        with open(file_path, 'r+b') as file_handle:
            file_handle.seek(security_directory_address)
            signature_size = struct.unpack('i', file_handle.read(4))[0]

        if signature_size < security_directory_size:

            temp_path = tempfile.TemporaryFile().name

            pe = pefile.PE(file_path)
            for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if data_directory.name == r'IMAGE_DIRECTORY_ENTRY_SECURITY':
                    data_directory.Size = signature_size
            pe.write(temp_path)
            pe.close()

            with open(temp_path, 'r+b') as file_handle:
                file_handle.seek(security_directory_address + signature_size)
                file_handle.truncate()

            os.remove(file_path)
            shutil.move(temp_path, file_path)


if __name__ == "__main__":
    back_to_original(sys.argv[1])

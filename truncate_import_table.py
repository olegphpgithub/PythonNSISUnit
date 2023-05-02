import os
import sys
import random
from typing import List

import pefile
import shutil
import datetime
import subprocess
import configparser
from collections import OrderedDict
from pathlib import Path


def import_descriptor_quantity(file_path):
    pe = pefile.PE(file_path)
    return len(pe.DIRECTORY_ENTRY_IMPORT)


def import_descriptor_inventory(file_path):
    pe = pefile.PE(file_path)
    inventory: List[str] = list()
    for module in pe.DIRECTORY_ENTRY_IMPORT:
        inventory.append(str(module.dll, r'utf-8').lower())
    return inventory


def delete_import_descriptor(file_path, library_name, shift_table=False):
    import_descriptor_absolute_offset = 0
    import_descriptor_shift_quantity = 0

    pe = pefile.PE(file_path)

    for module in pe.DIRECTORY_ENTRY_IMPORT:
        if import_descriptor_absolute_offset > 0:
            import_descriptor_shift_quantity += 1
        if str(module.dll, r'utf-8').lower() == library_name:
            if import_descriptor_absolute_offset == 0:
                import_descriptor_absolute_offset = module.struct.get_field_absolute_offset(r'OriginalFirstThunk')

    pe.close()

    if import_descriptor_absolute_offset > 0:
        with open(file_path, 'r+b') as file_handle:
            if shift_table:
                for i in range(import_descriptor_shift_quantity):
                    file_handle.seek(import_descriptor_absolute_offset + 20 * (i + 1))
                    import_descriptor_content = file_handle.read(20)
                    file_handle.seek(import_descriptor_absolute_offset + 20 * i)
                    file_handle.write(import_descriptor_content)
                file_handle.seek(import_descriptor_absolute_offset + 20 * import_descriptor_shift_quantity)
                file_handle.write(bytearray(20))
            else:
                file_handle.seek(import_descriptor_absolute_offset)
                file_handle.write(bytearray(20))


if __name__ == '__main__':

    source_file_path = r'd:\nnRus.Git\CppDownloader.03.SCB.REG\MultyHash\01_advapi32_shell32_shlwapi_kernel32_winmm_ole32_wininet_imm32.exe'
    source_file_name = os.path.basename(source_file_path)
    source_file_base = os.path.splitext(source_file_name)[0]
    source_file_dir = os.path.dirname(source_file_path)

    print(import_descriptor_quantity(source_file_path))

    library_list = import_descriptor_inventory(source_file_path)

    for library_file_name in library_list:
        library_base_name = os.path.splitext(library_file_name)[0]
        target_file_path = r'%s\%s_%s%s' % (source_file_dir, source_file_base, library_base_name, r'.exe')
        shutil.copy(source_file_path, target_file_path)
        delete_import_descriptor(target_file_path, library_file_name, True)

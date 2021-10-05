import sys
import pefile


def delete_import_descriptor(file_path, library_name):

    import_descriptor_absolute_offset = 0

    pe = pefile.PE(file_path)

    for module in pe.DIRECTORY_ENTRY_IMPORT:
        if str(module.dll, r'utf-8').lower() == library_name:
            import_descriptor_absolute_offset = module.struct.get_field_absolute_offset(r'OriginalFirstThunk')

    pe.close()

    if import_descriptor_absolute_offset > 0:
        with open(file_path, 'r+b') as file_handle:
            file_handle.seek(import_descriptor_absolute_offset)
            file_handle.write(bytearray(20))


if __name__ == "__main__":
    delete_import_descriptor(sys.argv[1], r'kernel32.dll')

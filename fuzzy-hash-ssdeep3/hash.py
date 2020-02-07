import sys
from ssdeep import hash, compare
from pefile import PE
from os import path


def get_import_table_hash(file_path):
    import_table_hash = ""
    try:
        import_table_string = get_import_table_string(file_path)
        if len(import_table_string) > 0:
            import_table_hash = hash(import_table_string)
    except Exception as e:
            print (e)
    return import_table_hash


def compare_files(file_path1, file_path2):
    hash1 = get_import_table_hash(file_path1)
    hash2 = get_import_table_hash(file_path2)
    return compare(hash1, hash2)


def get_import_table_string(file_path):
    import_table_bytes = b''
    import_table_string = ''
    try:
        pe = PE(file_path, fast_load=True)
        pe.parse_data_directories()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # import_table_string += str(entry.dll)
            for imp in entry.imports:
                # import_table_string += hex(imp.address)
                try:
                    import_table_bytes += imp.name
                    import_table_string += imp.name.decode("utf-8") + '\n'
                except:
                    pass
    except Exception as e:
        print(e)

    f = open(file_path + ".log", "w+")
    f.write(import_table_string)
    return import_table_bytes


def compare_files(file1, file2):
    if path.exists(file1):
        if path.exists(file2):
            fuzzy_hash1 = get_import_table_hash(file1)
            print("fuzzy_hash1: " + str(fuzzy_hash1))

            fuzzy_hash2 = get_import_table_hash(file2)
            print("fuzzy_hash2: " + str(fuzzy_hash2))

            compare_res = compare(fuzzy_hash1, fuzzy_hash2)
            print("compare12: " + str(compare_res))
        else:
            print("file2 not exists: " + file2)
    else:
        print("file1 not exists: " + file1)


if __name__ == "__main__":
    mode = None
    try:
        mode = str(sys.argv[1])
    except:
        pass

    if mode == '-calc':
        if len(sys.argv) == 3:
            file_path = str(sys.argv[2])
            if path.exists(file_path):
                fuzzy_hash1 = get_import_table_hash(file_path)
                print("fuzzy_hash1: " + str(fuzzy_hash1))
            else:
                print("file not exists: " + file_path)
        else:
            print("arguments exception")
    elif mode == '-compare':
        if len(sys.argv) == 4:
            file_path1 = str(sys.argv[2])
            file_path2 = str(sys.argv[3])
            compare_files(file_path1, file_path2)
        else:
            print("arguments exception")
    else:
        file_path1 = "files\\file1.dat"
        file_path2 = "files\\file2.dat"
        compare_files(file_path1, file_path2)


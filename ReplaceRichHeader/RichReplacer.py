import argparse
import os
import random
import struct
import sys

try:
    from colorama import init, Back
except ImportError:
    print('\n#########################################')
    print('Colorama module not found.')
    print('Colors replaced with brackets "[".')
    print('Use "pip install colorama" to add colors.')
    print('#########################################\n')

    def init():
        pass

    class Back:
        RED = '['
        GREED = '['
        BLACK = '['
        CYAN = '['
        RESET = ']'

RICH = b'\x52\x69\x63\x68'  # 1751345490 == b'\x52\x69\x63\x68' == b'Rich'
DANS = 1147235923           # 1147235923 == b'\x44\x61\x6e\x53' == b'DanS'


def get_files_from_dir(dir_path, search_rich=False):
    if search_rich:
        ext = '.rich'
    else:
        ext = ('.exe', '.dll')
    if os.path.isfile(dir_path):
        return [dir_path]
    result = []
    dir_objects = os.listdir(dir_path)
    for o in dir_objects:
        tmp_path = os.path.join(dir_path, o)
        if os.path.isfile(tmp_path) and tmp_path.endswith(ext):
            result.append(tmp_path)
    return result


def get_rich_boundaries(data, e_lfanew):
    global RICH, DANS
    tail = 0
    head = 0
    xor_key = 0
    j = e_lfanew - 4

    while j >= 0x80:
        if head == 0:
            if data[j:j + 4] == RICH:
                head = j + 8
                xor_key = int.from_bytes(data[j + 4:head], 'big')
                j -= 3
        else:
            if int.from_bytes(data[j:j + 4], 'big') ^ xor_key == DANS:
                tail = j
                break
        j -= 1

    return tuple((tail, head))


def update_checksum(data, e_lfaneww):
    # e_lfanew = int.from_bytes(data[0x3c:0x40], 'little')
    checksum_offset = e_lfaneww + 4 + 20 + 64

    checksum = 0
    remainder = len(data) % 4
    data_len = len(data) + ((4 - remainder) * (remainder != 0))

    for i in range(int(data_len / 4)):
        if i == int(checksum_offset / 4):  # Skip the checksum field
            continue
        if i + 1 == (int(data_len / 4)) and remainder:
            dword = struct.unpack('I', data[i * 4:] + (b'\0' * (4 - remainder)))[0]
        else:
            dword = struct.unpack('I', data[i * 4: i * 4 + 4])[0]
        checksum += dword
        if checksum >= 2 ** 32:
            checksum = (checksum & 0xffffffff) + (checksum >> 32)

    checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = checksum + (checksum >> 16)
    checksum = checksum & 0xffff
    checksum = checksum + len(data)

    checksum_bytes = checksum.to_bytes(4, 'little')
    return data[:checksum_offset] + checksum_bytes + data[checksum_offset + 4:]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Replace Rich header', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-in', dest='in_file', metavar='file\\or\\dir', required=True, type=str,
                        help='Path to the target PE file or files.\n'
                             'To input a file, it is necessary to specify the extension (".exe" or ".dll") in path.\n'
                             'If the only argument, shows the required length of the Rich header.')
    parser.add_argument('-rich', dest='rich_file', metavar='file\\or\\dir', type=str, default=None,
                        help='Path to the rich file or files.\n'
                             'Rich files must be created using a "Rich_search.py".')
    parser.add_argument('-out', dest='out_dir', metavar='file\\or\\dir', type=str,
                        help='Path to place the output file. Default is script directory.\n'
                             'To output to a file, it is necessary to specify the extension (".exe" or ".dll") in path.')
    parser.add_argument('-rnd', action='store_true', help='modify input file or files with random rich file.')
    parser.add_argument('-not-overwrite', dest='not_overwrite', action='store_true', help='do not overwrite files if names match.')
    parser.add_argument('-v', dest='verbose', action='store_true', help='enable verbose output.')
    initargs = parser.parse_args()

    src = initargs.in_file
    rich_path = initargs.rich_file
    if initargs.out_dir:
        dst = initargs.out_dir
    else:
        dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_rich_samples')
    dst_is_file = dst.endswith(('.exe', '.dll'))

    init()

    if not os.path.exists(src):
        print(f"{Back.RED}Can't access to source file: {src}{Back.RESET}")
        print('Exiting the program.')
        sys.exit(2)

    source_files = get_files_from_dir(src)
    for sf in source_files:
        pass
        with open(sf, 'rb') as f:
            pe_data = bytearray(f.read())

        eof = len(pe_data)
        pe_e_lfanew = int.from_bytes(pe_data[0x3c:0x40], 'little')
        if pe_e_lfanew == 0 or pe_e_lfanew >= eof:
            print(f'{Back.RED}File {os.path.split(sf)[1]} contains invalid e_lfanew value: {hex(pe_e_lfanew)}.{Back.RESET}')
            continue

        rb = get_rich_boundaries(pe_data, pe_e_lfanew)
        tail_offset = rb[0]
        head_offset = rb[1]

        if 0 < tail_offset < head_offset:
            rich_len = head_offset - tail_offset
            print(f'{Back.BLACK}{os.path.split(sf)[1]} required rich length <= {rich_len}.{Back.RESET}')

            if not rich_path:
                continue
            if not os.path.exists(dst) and not dst_is_file:
                try:
                    os.makedirs(dst)
                except WindowsError:
                    print(f"{Back.RED}Can't create container folder: {dst}{Back.RESET}")
                    print('Exiting the program.')
                    sys.exit(2)
            if not os.path.exists(rich_path):
                print(f"{Back.RED}Can't access to rich file: {rich_path}{Back.RESET}")
                print('Exiting the program.')
                sys.exit(2)

            rich_files = get_files_from_dir(rich_path, search_rich=True)

            if initargs.rnd:
                tmp_files = []
                for rf in rich_files:
                    try:
                        check = int(os.path.split(rf)[1].split('-')[0])
                    except Exception as e:
                        print(f'An exception occurred with the rich file {os.path.split(rf)[1]}:')
                        print(e)
                        continue
                    if check <= rich_len:
                        tmp_files.append(rf)
                if len(tmp_files) == 0:
                    print(f'No suitable rich file for modification {os.path.split(sf)[1]}.')
                    continue
                rich_files = [tmp_files[random.randint(0, 32767) % len(tmp_files)]]

            for rf in rich_files:
                with open(rf, 'rb') as f:
                    donor = bytearray(f.read())
                donor_len = len(donor)

                if rich_len < donor_len:
                    if initargs.verbose:
                        print(f'Selected rich file {os.path.split(rf)[1]} is too large.')
                        print(f'Required rich length <= {rich_len}, but was {donor_len}.')
                    continue

                new_data = pe_data[:tail_offset] + donor + b'\x00' * (rich_len - donor_len) + pe_data[head_offset:]
                new_data = update_checksum(new_data, pe_e_lfanew)

                if dst_is_file:
                    pe_path = dst
                else:
                    rich_file_src_name = os.path.splitext(os.path.basename(rf))[0].split('-')[-1]
                    new_pe_name = f'rich_from-{rich_file_src_name}_{os.path.split(sf)[1]}'
                    pe_path = os.path.join(dst, new_pe_name)

                if initargs.not_overwrite:
                    if os.path.exists(pe_path):
                        file_counter = 1
                        sample_name_ext = os.path.splitext(pe_path)
                        while os.path.exists(pe_path):
                            pe_path = f'{sample_name_ext[0]}_{file_counter}{sample_name_ext[1]}'
                            file_counter += 1

                with open(pe_path, 'wb') as rich:
                    rich.write(new_data)
                print(f'{Back.BLACK}Donor: {os.path.split(rf)[1]} with length {donor_len}.{Back.RESET}')
                print(f'File saved as: {pe_path}')
        else:
            print(f'{Back.CYAN}File {os.path.split(sf)[1]} does not contain "Rich" header.{Back.RESET}')

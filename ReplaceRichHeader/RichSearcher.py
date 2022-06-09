import argparse
import os
from pathlib import Path
import sys

RICH = b'\x52\x69\x63\x68'  # 1751345490 == b'\x52\x69\x63\x68' == b'Rich'
DANS = 1147235923           # 1147235923 == b'\x44\x61\x6e\x53' == b'DanS'

parser = argparse.ArgumentParser(description='Search Rich headers')
parser.add_argument('-s', metavar='path\\to\\dir', required=True, type=str, help='search directory path.')
parser.add_argument('-c', metavar='path\\to\\dir', type=str, help='container directory path. the default is the script directory.')
parser.add_argument('-len', metavar='rich_length', type=int, default=0, help='required length of Rich header. omit for any.')
parser.add_argument('-limit', metavar='count', type=int, default=0, help='limit on the number of samples. omit for all possible.')
parser.add_argument('-not-overwrite', dest='not_overwrite', action='store_true', help='do not overwrite files if names match.')
initargs = parser.parse_args()

src = initargs.s
if initargs.c:
    dst = initargs.c
else:
    dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_rich_hdrs')
req_len = initargs.len
count = 0
limit = initargs.limit

if not os.path.exists(src):
    print(f"Can't access to search directory: {src}")
    sys.exit(2)

if not os.path.exists(dst):
    try:
        os.makedirs(dst)
    except WindowsError:
        print(f"Can't create container folder: {dst}")
        sys.exit(2)

if req_len < 0:
    print(f'Required length of Rich header cannot be less then zero.')
    print(f'Specified value: {req_len}.')
    sys.exit(2)

for dirpath, dirnames, filenames in os.walk(src):
    for filename in [f for f in filenames if f.endswith(".exe") or f.endswith(".dll")]:
        pe_path = os.path.join(dirpath, filename)
        with open(pe_path, 'rb') as f:
            data = bytearray(f.read())

        eof = len(data)
        e_lfanew = int.from_bytes(data[0x3c:0x40], 'little')
        if e_lfanew == 0 or e_lfanew >= eof:
            continue

        tail_offset = 0
        head_offset = 0
        xor_key = 0
        j = e_lfanew - 4

        while j >= 0x80:
            if head_offset == 0:
                if data[j:j + 4] == RICH:
                    head_offset = j + 8
                    xor_key = int.from_bytes(data[j + 4:head_offset], 'big')
                    j -= 3
            else:
                if int.from_bytes(data[j:j + 4], 'big') ^ xor_key == DANS:
                    tail_offset = j
                    break
            j -= 1

        if 0 < tail_offset < head_offset:
            rich_len = head_offset - tail_offset
            if req_len:
                if req_len < rich_len:
                    continue

            src_name = Path(filename).stem
            rich_data = data[tail_offset:head_offset]
            rich_name = f'{rich_len}-rich_len_SOURCE-{src_name}.rich'
            rich_path = os.path.join(dst, rich_name)

            if initargs.not_overwrite:
                if os.path.exists(rich_path):
                    file_counter = 1
                    while os.path.exists(rich_path):
                        rich_name = f'{rich_len}-rich_len_SOURCE-{src_name}_{file_counter}.rich'
                        rich_path = os.path.join(dst, rich_name)
                        file_counter += 1

            print(rich_name)
            with open(rich_path, 'wb') as rich:
                rich.write(rich_data)

            count += 1
            if limit:
                if limit <= count:
                    print(f'Limit reached.')
                    print(f'Files saved in: {dst}')
                    sys.exit(0)

if count > 0:
    print(f'Files saved in: {dst}')
else:
    print('Nothing found.')

#!/usr/bin/env python

import argparse
import io
import os
import pathlib


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-с", "--count", required=True, type=int)
    args = parser.parse_args()

    try:
        f = open(args.file, 'rb')
        f.seek(0, io.SEEK_END)
        file_size = f.tell()
        part_size = int(file_size / args.count)

        f.seek(0, io.SEEK_SET)
        buffer_size = 16

        counter = 0
        while file_size > f.tell():

            output_file_path = os.path.dirname(args.file) \
                               + os.sep \
                               + pathlib.Path(args.file).stem \
                               + r'_' \
                               + str(counter) \
                               + pathlib.Path(args.file).suffix

            output_file_handle = open(output_file_path, 'wb')

            while part_size * (counter + 1) > f.tell():
                remain_size = part_size * (counter + 1) - f.tell()
                read_size = buffer_size if remain_size > buffer_size else remain_size
                buffer = f.read(read_size)
                output_file_handle.write(buffer)

                if (file_size - f.tell()) < args.count:
                    buffer = f.read(read_size)
                    output_file_handle.write(buffer)

            output_file_handle.close()

            counter = counter + 1

    except OSError:
        sys.exit(-1)

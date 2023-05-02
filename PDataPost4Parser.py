import os
import re
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, r"Output")
PDATAPOST4_FILE_TXT = r'e:\NetNucleusRus\Diary\2022\2022-07\2022-07-18\12-20_Charity\PDATAPOST4-2022-07-15.txt'


def write_list_to_file(file_name, item_list):
    output_file_name = "%s/%s%s" % (OUTPUT_DIR, file_name, ".txt")
    f = open(output_file_name, "ab")
    for item in item_list:
        f.write(item)
        f.write(b"\n")
    f.close()


def select_records_by_ip(file_prefix, file_suffix, file_path):
    with open(file_path, 'rb') as file_handle:
        content = file_handle.read()
        file_lines = content.split(b"\n")
        lines = list()
        for file_line in file_lines:
            lines.append(file_line)
            if file_line.find(b'-NNCDIV--NNCRECDIV-') > -1:
                line = file_line.decode("latin1")
                m = re.search(r'-NNCDIV-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-NNCDIV-(\d+)-NNCDIV--NNCRECDIV-', line)
                if m is not None:
                    ip = m.group(1)
                    if lines[0][:4] == b'v15 ':
                        for log_entry in lines:
                            m_log = re.search(
                                r'charityengine-install-log.txt', log_entry)
                            if m_log is not None:

                        write_list_to_file("%s%s%s" % (file_prefix, ip, file_suffix), lines)
                lines = list()


if __name__ == "__main__":

    select_records_by_ip('', '-v15', PDATAPOST4_FILE_TXT)
    # select_records_by_ip('', '-process', PROCESS_LIST_FILE_TXT)

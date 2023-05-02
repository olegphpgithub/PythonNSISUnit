import os
import re
import mysql.connector
from datetime import datetime

from local_settings import *

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, r"Output")
ADD_REMOVE_LIST_FILE_TXT = r'e:\NetNucleusRus\log\ADDR\ADDR-2020-02-17.txt'
PROCESS_LIST_FILE_TXT = r'e:\NetNucleusRus\log\POSTTEST\POSTTEST-2020-02-17.txt'
PDATAPOST4_FILE_TXT = r'e:\NetNucleusRus\log\PDATAPOST4\example.txt'

ip_list = 0


def build_query(start, finish):
    with open(r'sql\addr_query.sql', 'r') as query_file:
        query_string = query_file.read().replace('\n', ' ')
    query_string = query_string.replace(r'@DateTime1', start.strftime("'%Y-%m-%d %H:%M:%S'"))
    query_string = query_string.replace(r'@DateTime2', finish.strftime("'%Y-%m-%d %H:%M:%S'"))
    return query_string


def build_ip_list():
    global ip_list
    start = datetime.strptime('2020-02-17 00:00:00', "%Y-%m-%d %H:%M:%S")
    finish = datetime.strptime('2020-02-18 00:00:00', "%Y-%m-%d %H:%M:%S")
    query_string = build_query(start, finish)
    print(query_string)
    cur.execute(query_string)
    for row1 in cur.fetchall():
        ip_list.append(row1[0])


def write_list_to_file(file_name, item_list):
    output_file_name = "%s/%s%s" % (OUTPUT_DIR, file_name, ".txt")
    f = open(output_file_name, "ab")
    for item in item_list:
        f.write(item)
        f.write(b"\n")
    f.close()


def select_records_by_ip(file_prefix, file_suffix, file_path):
    global ip_list
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
                    if ip in ip_list:
                        write_list_to_file("%s%s%s" % (file_prefix, ip, file_suffix), lines)
                lines = list()


def fetch_ip_by_string(file_path, needle):
    ips = list()
    with open(file_path, 'rb') as file_handle:
        content = file_handle.read()
        file_lines = content.split(b"\n")
        occurrence = False
        for file_line in file_lines:
            if file_line.find(needle) > -1:
                occurrence = True

            if occurrence:
                line = file_line.decode("latin1")
                m = re.search(r'-NNCDIV-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-NNCDIV-(\d+)-NNCDIV--NNCRECDIV-', line)
                if m is not None:
                    ips.append(m.group(1))
                    occurrence = False
    return ips


if __name__ == "__main__":

    ip_list = list()

    db = mysql.connector.connect(
        host=local_settings_mysql_host,
        user=local_settings_mysql_user,
        password=local_settings_mysql_password,
        db=local_settings_mysql_db
    )

    print("connect successful!!!")

    cur = db.cursor()

    build_ip_list()

    select_records_by_ip('', '-add_remove', ADD_REMOVE_LIST_FILE_TXT)
    select_records_by_ip('', '-process', PROCESS_LIST_FILE_TXT)

    ips = fetch_ip_by_string(PDATAPOST4_FILE_TXT, b'522 Origin Connection Time-out')
    for ipo in ips:
        print(ipo)

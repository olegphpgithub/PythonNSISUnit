import os
import re
from collections import OrderedDict
from operator import itemgetter
import mysql.connector
from datetime import datetime
import openpyxl
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment
import openpyxl.styles
from openpyxl.styles.borders import Border, Side
from openpyxl import Workbook

from local_settings import *

ip_list = list()
add_remove_dict = OrderedDict()


def build_query(start, finish):

    with open(r'sql\addr_query.sql', 'r') as query_file:
        query_string = query_file.read().replace('\n', ' ')

    query_string = query_string.replace(r'@DateTime1', start.strftime("'%Y-%m-%d %H:%M:%S'"))
    query_string = query_string.replace(r'@DateTime2', finish.strftime("'%Y-%m-%d %H:%M:%S'"))

    return query_string


def build_ip_list():
    start = datetime.strptime('2019-06-21 18:00:00', "%Y-%m-%d %H:%M:%S")
    finish = datetime.strptime('2019-06-21 19:00:00', "%Y-%m-%d %H:%M:%S")
    query_string = build_query(start, finish)
    print(query_string)
    cur.execute(query_string)
    for row1 in cur.fetchall():
        ip_list.append(row1[0])
    print(len(ip_list))
    for ip in ip_list:
        print(ip)


def read_file():
    with open(r'e:\NetNucleusRus\log\POSTTEST\POSTTEST2019621.txt', 'rb') as addr_file:
        content = addr_file.readlines()
        add_remove_list = list()
        for line in content:
            if line.find("-NNCDIV--NNCRECDIV-") > -1:
                m = re.search(r'-NNCDIV-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-NNCDIV-(\d+)-NNCDIV--NNCRECDIV-', line)
                if m is not None:
                    ip = m.group(1)
                    if ip in ip_list:
                        ip_list.remove(ip)
                        for add_remove_item in add_remove_list:
                            if add_remove_item in add_remove_dict.keys():
                                add_remove_dict[add_remove_item] = add_remove_dict[add_remove_item] + 1
                            else:
                                add_remove_dict[add_remove_item] = 1
                add_remove_list = list()
            else:
                m = re.search(r'\b([^\[]+)\[', line)
                if m is not None:
                    if m.group(1) not in add_remove_list:
                        add_remove_list.append(m.group(1))


def show_task_list():
    add_remove_dict_ord = OrderedDict(sorted(add_remove_dict.items(), key=itemgetter(1)))
    for add_remove_item in add_remove_dict_ord.keys():
        print("%s -> %s" % (add_remove_item, add_remove_dict_ord[add_remove_item]))


db = mysql.connector.connect(
    host=local_settings_mysql_host,
    user=local_settings_mysql_user,
    password=local_settings_mysql_password,
    db=local_settings_mysql_db
)

print ("connect successful!!!")

# Create a Cursor object to execute queries.
cur = db.cursor()

build_ip_list()
read_file()
show_task_list()



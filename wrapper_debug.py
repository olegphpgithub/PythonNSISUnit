import os
from os import path
import re
from collections import OrderedDict
import mysql.connector
from operator import itemgetter
from datetime import datetime

from local_settings import *

BASE_DIR = path.dirname(path.abspath(__file__))
QUERY_FILE = path.join(BASE_DIR, r'sql\wrapper_debug.sql')
message_list = list()
process_collection = OrderedDict()


def build_query(start, finish):

    with open(QUERY_FILE, 'r') as query_file:
        query_string = query_file.read().replace('\n', ' ')

    query_string = query_string.replace(r'@DateTime1', start.strftime("'%Y-%m-%d %H:%M:%S'"))
    query_string = query_string.replace(r'@DateTime2', finish.strftime("'%Y-%m-%d %H:%M:%S'"))

    return query_string


def build_array():
    global message_list
    start = datetime.strptime('2019-07-31 23:45:00', "%Y-%m-%d %H:%M:%S")
    finish = datetime.strptime('2019-08-01 00:00:00', "%Y-%m-%d %H:%M:%S")
    query_string = build_query(start, finish)
    print(query_string)
    cur.execute(query_string)
    for row1 in cur.fetchall():
        message_list.append(row1[2])


def build_report():
    global message_list
    global process_collection
    for message in message_list:
        matches = re.search(r'\[pr:(.*)\]', message)
        if matches is not None:
            process_list = matches.group(1)
            process_list_distinct = list()
            for process in process_list.split(r','):
                if process not in process_list_distinct:
                    process_list_distinct.append(process)
            for process in process_list_distinct:
                if process in process_collection:
                    process_collection[process] = process_collection[process] + 1
                else:
                    process_collection[process] = 1

    process_collection_sorted = OrderedDict(sorted(process_collection.items(), key=itemgetter(1)))
    for process in process_collection_sorted.keys():
        print(r"%s = %d" % (process, process_collection_sorted[process]))


db = mysql.connector.connect(
    host=local_settings_mysql_host,
    user=local_settings_mysql_user,
    password=local_settings_mysql_password,
    db=local_settings_mysql_db
)

print("connect successful!!!")

cur = db.cursor()

build_array()
build_report()

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
ip_list.append('76.90.231.103')
ip_list.append('98.214.222.101')
ip_list.append('24.88.201.46')
ip_list.append('166.182.251.195')
ip_list.append('74.67.76.216')
ip_list.append('69.9.222.2')
ip_list.append('67.5.12.220')
ip_list.append('73.61.8.124')
ip_list.append('98.223.252.29')
ip_list.append('72.82.160.10')
ip_list.append('205.201.68.235')
ip_list.append('70.191.168.24')
ip_list.append('98.156.231.86')
ip_list.append('97.99.230.71')
ip_list.append('47.219.230.61')
ip_list.append('98.202.220.117')
ip_list.append('108.28.109.7')
ip_list.append('99.139.78.5')
ip_list.append('76.170.67.236')
ip_list.append('75.161.93.22')
ip_list.append('67.166.225.18')
ip_list.append('173.21.87.84')
ip_list.append('65.191.174.163')
ip_list.append('99.185.227.253')
ip_list.append('73.176.22.90')
ip_list.append('69.137.119.215')
ip_list.append('45.16.227.134')
ip_list.append('74.254.159.199')
ip_list.append('67.79.237.195')
ip_list.append('98.22.66.146')
ip_list.append('108.251.230.78')
ip_list.append('108.74.135.24')
ip_list.append('68.37.239.61')
ip_list.append('162.246.150.163')
ip_list.append('73.218.234.174')
ip_list.append('66.191.48.83')
ip_list.append('68.230.6.188')
ip_list.append('172.8.190.187')
ip_list.append('162.201.49.94')
ip_list.append('76.125.221.30')
ip_list.append('98.252.73.222')
ip_list.append('71.195.170.71')
ip_list.append('69.1.38.63')
ip_list.append('24.18.52.16')
ip_list.append('72.179.53.214')

add_remove_dict = OrderedDict()
process_dict = OrderedDict()

ip_distinct = dict()

ip_who_send = 0
ip_who_less = 0
ip_who_more = 0
ip_who_none = 0


def build_query(start, finish):

    with open(r'sql\addr_query.sql', 'r') as query_file:
        query_string = query_file.read().replace('\n', ' ')

    query_string = query_string.replace(r'@DateTime1', start.strftime("'%Y-%m-%d %H:%M:%S'"))
    query_string = query_string.replace(r'@DateTime2', finish.strftime("'%Y-%m-%d %H:%M:%S'"))

    return query_string


def build_ip_list():
    global ip_list
    start = datetime.strptime('2019-08-17 23:20:00', "%Y-%m-%d %H:%M:%S")
    finish = datetime.strptime('2019-08-18 02:50:00', "%Y-%m-%d %H:%M:%S")
    query_string = build_query(start, finish)
    print(query_string)
    cur.execute(query_string)
    for row1 in cur.fetchall():
        ip_list.append(row1[0])
    # for ip in ip_list:
        # print(ip)


def read_addr_file():
    global ip_who_send
    global ip_who_less, ip_who_more, ip_who_none, ip_distinct
    global ip_list
    # with open(r'e:\NetNucleusRus\Diary\2019\2019-08-18\12-00_parser\ADDR2019818.txt', 'rb') as addr_file:
    with open(r'e:\NetNucleusRus\Diary\2019\2019-08-18\12-00_parser\total_ad.txt', 'rb') as addr_file:
        content = addr_file.readlines()
        add_remove_list = list()
        for line in content:
            if line.find("-NNCDIV--NNCRECDIV-") > -1:
                m = re.search(r'-NNCDIV-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-NNCDIV-(\d+)-NNCDIV--NNCRECDIV-', line)
                if m is not None:
                    ip = m.group(1)
                    if ip in ip_list:
                        ip_list.remove(ip)
                        if ip not in ip_distinct:
                            ip_distinct[ip] = 1
                        else:
                            ip_distinct[ip] = ip_distinct[ip] + 1
                        ip_who_send = ip_who_send + 1

                        count_enum = 1
                        """
                        for add_remove_item in add_remove_list:
                            if (add_remove_item.find(r'less than 10 points') != -1):
                                count_enum = 1
                                break
                            if (add_remove_item.find(r'more than 10 points') != -1):
                                count_enum = 2
                                break
"""
                        if count_enum == 1:
                            ip_who_less = ip_who_less + 1
                            file_name = r'd:\PythonMasterReport\less\%s_a[%s].txt' % (ip, ip_distinct[ip])
                            f = open(file_name, r'w')
                            f.write("\n")
                            f.write("\n")
                            f.write(ip)
                            f.write("\n")
                            f.write("//******************* add/remove list ***********************//")
                            f.write("\n")
                            print(ip)
                            for add_remove_item in add_remove_list:
                                f.write(add_remove_item)
                                f.write("\n")
                            f.close()
                        elif count_enum == 2:
                            ip_who_more = ip_who_more + 1
                        else:
                            ip_who_none = ip_who_none + 1

                            # if add_remove_item in add_remove_dict.keys():
                                # add_remove_dict[add_remove_item] = add_remove_dict[add_remove_item] + 1
                            # else:
                                # add_remove_dict[add_remove_item] = 1
                add_remove_list = list()
            else:
                add_remove_list.append(line.strip())


def read_process_file():
    global process_dict, ip_list
    with open(r'e:\NetNucleusRus\log\POSTTEST\total.txt', 'rb') as process_file:
        content = process_file.readlines()
        process_list = list()
        for line in content:
            if line.find("-NNCDIV--NNCRECDIV-") > -1:
                m = re.search(r'-NNCDIV-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-NNCDIV-(\d+)-NNCDIV--NNCRECDIV-', line)
                if m is not None:
                    ip = m.group(1)
                    if ip in ip_list:
                        ip_list.remove(ip)
                        print("")
                        print("")
                        print(m.group(1))
                        for process_item in process_list:
                            process_dict[ip]
                process_list = list()
            else:
                process_list.append(line.strip())


db = mysql.connector.connect(
    host=local_settings_mysql_host,
    user=local_settings_mysql_user,
    password=local_settings_mysql_password,
    db=local_settings_mysql_db
)

print("connect successful!!!")

# Create a Cursor object to execute queries.
cur = db.cursor()

# build_ip_list()
print(len(ip_list))

# read_process_file()


read_addr_file()
print("sent = %s" % ip_who_send)
print("less = %s" % ip_who_less)
print("more = %s" % ip_who_more)
print("none = %s" % ip_who_none)

#print(len(add_remove_dict))

#add_remove_dict = OrderedDict(sorted(add_remove_dict.items(), key=itemgetter(1)))
#for add_remove_item in add_remove_dict.keys():
#    print("%s -> %s" % (add_remove_item, add_remove_dict[add_remove_item]))

# for ip in ip_list:
    # print(ip)

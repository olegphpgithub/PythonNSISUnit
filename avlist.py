
import os
from collections import OrderedDict
import mysql.connector
from datetime import datetime
import openpyxl
from openpyxl.utils import get_column_letter
from openpyxl.styles import Alignment
import openpyxl.styles
from openpyxl.styles.borders import Border, Side
from openpyxl import Workbook

from local_settings import *

db = mysql.connector.connect(
    host=local_settings_mysql_host,
    user=local_settings_mysql_user,
    password=local_settings_mysql_password,
    db=local_settings_mysql_db
)

print ("connect successful!!!")

# Create a Cursor object to execute queries.
cur = db.cursor()

query_string = "select distinct ip from installer where stime>@DateTime1 and stime<date_add(@DateTime2, interval 15 minute) and action in (2062) \
and (date(stime), ip) in (select * from (select distinct date(stime),ip from installer where stime>@DateTime1 and stime<@DateTime2 and action=2940) as subq1) \
and (date(stime), ip) in (select * from (select distinct date(stime),ip from installer where stime between @DateTime1 and date_add(@DateTime2, interval 15 minute) and action=9902) as subq2) \
and (date(stime), ip) not in (select * from (select distinct date(stime),ip from installer where stime between @DateTime1 and date_add(@DateTime2, interval 15 minute) and action=2064) as subq2) \
and installer.country in ('US', 'CA')"


start = datetime.strptime("2019-04-21 00:00:00", "%Y-%m-%d %H:%M:%S")
finish = datetime.strptime("2019-04-22 00:00:00", "%Y-%m-%d %H:%M:%S")

query_string = query_string.replace(r'@DateTime1', start.strftime("'%Y-%m-%d %H:%M:%S'"))
query_string = query_string.replace(r'@DateTime2', finish.strftime("'%Y-%m-%d %H:%M:%S'"))

print(query_string)

cur.execute(query_string)

for row1 in cur.fetchall():
    # print row1[0]
    with open(r"d:\PythonMasterReport\PDATAPOST42019421.txt", "r+") as log_file:
        log_lines = log_file.readlines()
        log_file.seek(0)
        for index, line in enumerate(log_lines):
            if line.find(row1[0]) >= 0:
                if line.find(r"v10 ") >= 0:
                    print(line)


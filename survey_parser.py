import os
import re
import hashlib
import datetime
import mysql.connector

from survey_parser_settings import *

RECORD_TEMPLATE = b'^%s(.+)-NNCDIV-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-NNCDIV-(\d+)-NNCDIV-'
SUBMIT_TEMPLATE = r'\[.+\\(\d+)\].*"BundleOfferActionUid"="([^\"]*)"'
PARAM1_TEMPLATE = r'"([^\"]+)"="([^\"]*)"'

db = 0
cur = 0


class Survey:
    def __init__(self, ip, ts, campaign, bundle, question, answer):
        self.downloads = 0
        self.ip = ip
        self.ts = ts
        self.campaign = campaign
        self.bundle = bundle
        self.question = question
        self.answer = answer


survey_list = list();


def read_survey_file():

    global survey_list

    with open(r'e:\NetNucleusRus\log\PDATAPOST4\PDATAPOST4-2020-11-22.txt', r'rb') as survey_file:
        content = survey_file.read()
        storage = content.split(b'-NNCRECDIV-')
        for record in storage:
            record = record.strip()
            m = re.search(RECORD_TEMPLATE % b'v76\s', record)
            if m is not None:
                rw = m.group(1).decode('latin-1')
                ip = m.group(2).decode('latin-1')
                ts = int(m.group(3))
                keys = rw.split(r'[')
                del keys[0]

                for i, v in enumerate(keys):
                    keys[i] = r'[' + v.strip()

                for key in keys:
                    bundle_match = re.search(SUBMIT_TEMPLATE, key)
                    if bundle_match is not None:
                        campaign = bundle_match.group(1)
                        bundle = bundle_match.group(2)
                        values = key.split(r'|')
                        for value in values:
                            value_match = re.search(PARAM1_TEMPLATE, value)
                            if value_match is not None:
                                question = value_match.group(1)
                                answer = value_match.group(2)
                                # if not answer and question != "BundleOfferActionUid":
                                #     continue
                                survey_list.append(Survey(ip, ts, campaign, bundle, question, answer))


def write_survey_list_to_db():

    global survey_list
    global db
    global cur

    for survey in survey_list:

        query_template = r'INSERT INTO survey VALUES(NULL, "%s", %s, %d, "%s", %s)'

        dt = datetime.datetime.utcfromtimestamp(survey.ts)
        u_time = dt.strftime('%Y-%m-%d %H:%M:%S')
        s_time = r"convert_tz('%s', '+00:00', 'US/Eastern')" % u_time

        query_string = query_template % (u_time, s_time, survey.ts, survey.ip, r'%s, %s, %s, %s')

        try:
            cur.execute(query_string, (survey.campaign, survey.bundle, survey.question, survey.answer))
        except mysql.connector.Error as err:
            print("Could not execute query: {}".format(err))

    db.commit()


def connect_to_db():

    global db
    global cur

    db = mysql.connector.connect(
        host=local_settings_mysql_host,
        user=local_settings_mysql_user,
        password=local_settings_mysql_password,
        db=local_settings_mysql_db
    )

    print("Connect successful!!!")

    cur = db.cursor()


if __name__ == r'__main__':
    connect_to_db()
    read_survey_file()
    write_survey_list_to_db()


"""

DROP TABLE `survey`;

CREATE TABLE `survey`
(
    `record_id` INTEGER primary key auto_increment,
    `utime` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `stime` TIMESTAMP NOT NULL,
    `xtime` INTEGER NOT NULL,
    `ip` VARCHAR(15) NOT NULL,
    `campaign` INTEGER NOT NULL,
    `bundle` VARCHAR(64) NOT NULL,
    `question` VARCHAR(64) NOT NULL,
    `answer` VARCHAR(64),
    UNIQUE KEY (`xtime`, `ip`, `campaign`, `bundle`, `question`)
)
;

TRUNCATE TABLE `survey`;
ALTER TABLE `survey` AUTO_INCREMENT = 1;

"""

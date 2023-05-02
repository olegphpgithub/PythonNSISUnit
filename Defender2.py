import os

import urllib3
import gzip
import shutil

import pathlib


class User:
    ip = ""
    detections = list()
    timestamp = ""

# replace all non readable chars from file
def prepareFileForTextView(path):
    fh = open(path, 'rb')
    out = bytearray()
    ba = bytearray(fh.read())
    fh.close()
    for byte in ba:
        if ((byte != 10) & (byte != 13)):
            if (byte < 0x09) or (byte > 0x7F):
                byte = 0x2A
        out.append(byte)
    #os.remove(path)
    fo = open(path+".clr", 'wb')
    fo.write(out)


def downloadFile(url, path):
    http = urllib3.PoolManager()
    response = http.request('GET', url)

    meta = response.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    print("Downloading: %s Bytes: %s" % (path, file_size))
    if file_size > 1000:
        f = open(path, 'wb')
        f.write(response.data)
        f.close()
        return "ok"
    else:
        return "error"


def unzipFile(zipFile, outFile):
    with gzip.open(zipFile, 'rb') as f_in:
        with open(outFile, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

def ParseFile(fileName):

    defenderRecords = list()

    # read file
    with open(fileName, "r") as input:
        lines = input.read()
        records = lines.split("-NNCRECDIV-")
        for record in records:
            if record.find("Win32/") >= 0:
                defenderRecords.append(record)

        return defenderRecords


def parseRecords(records):
    for record in records:
        strings = record.split("-NNCDIV-")
        User = User()
        user

def getDefenderStatustic(year, month, day, output_folder):
    url = "http://172.245.127.190/write/PDATAPOST4{:04d}{:d}{:d}.txt".format(year, month, day)
    rootpath = output_folder + "PDATAPOST4{:04d}{:d}{:d}.txt".format(year, month, day)
    # try download txt file
    if downloadFile(url, rootpath) != "ok":
        if downloadFile(url + ".gz", rootpath + ".gz") == "ok":
            # unzip file
            unzipFile(rootpath + ".gz", rootpath)
            try:
                os.remove(rootpath + ".gz")
            except OSError:
                print("error delete gz file")
                return
        else:
            print("error download file")
            return
    prepareFileForTextView(rootpath)
    records = ParseFile(rootpath+".clr")
    parseRecords(records)


rootPath = "D:\\"
# rootPath = pathlib.Path(__file__).parent.absolute()

getDefenderStatustic(year=2020, month=9, day=17, output_folder="d:\\")

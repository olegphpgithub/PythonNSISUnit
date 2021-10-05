#!/usr/bin/env python

import argparse
import re
from enum import Enum, auto
from random import choice
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import ExtensionNotFound

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--main", default=None)
parser.add_argument("-c", "--chain", default=None)
parser.add_argument("-r", "--random", action="store_true")
parser.add_argument("-i", "--input-file", required=True)
parser.add_argument("-o", "--output-file", required=True)
args = parser.parse_args()
if not (args.main or args.chain or args.random):
    parser.error("one of the arguments --main, --chain, --random is required")


class CertificateType(Enum):
    UNKNOWN = auto()
    MAIN = auto()
    CHAIN = auto()
    TIMESTAMP = auto()


class Certificate:
    type: CertificateType
    byte_offset: int
    _x509: x509.Certificate

    def __init__(self, data: str, byte_offset: int):
        self.byte_offset = byte_offset
        try:
            self._x509 = x509.load_der_x509_certificate(
                bytes.fromhex(data), default_backend()
            )
            bc = self._x509.extensions.get_extension_for_class(x509.BasicConstraints)
            ku = self._x509.extensions.get_extension_for_class(x509.KeyUsage)
            eku = self._x509.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            if x509.oid.ExtendedKeyUsageOID.CODE_SIGNING in eku.value:
                if bc.value.ca is True and ku.value.key_cert_sign is True:  # noqa
                    self.type = CertificateType.CHAIN
                else:
                    self.type = CertificateType.MAIN
            elif eku.value == x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]
            ):
                self.type = CertificateType.TIMESTAMP
            else:
                raise ValueError
        except (ValueError, ExtensionNotFound):
            self.type = CertificateType.UNKNOWN

    def is_valid(self) -> bool:
        return self.type is not CertificateType.UNKNOWN


class Patcher:
    _path: str = str()
    _data: str = str()
    _cert_pattern: str = "3082(?:05|06)"
    _seq_pattern: str = "300d06092a864886f70d01010b..000382"
    _certificates: List[Certificate] = list()
    # fmt: off
    _bytes: List[str] = [
        "00", "01", "03", "06", "10", "11",
        "21", "22", "23", "25", "26", "2a",
    ]
    # fmt: on

    def __init__(self, file_path: str):
        self._path = file_path
        self._read_file()
        self._certificates = list()
        self._search_certificates()

    def _read_file(self):
        with open(self._path, "rb") as file:
            self._data = file.read().hex()

    def _patch(self, offset: int, byte: str):
        before = slice(None, offset)
        after = slice(offset + 2, None)
        self._data = self._data[before] + byte + self._data[after]
        print(f"Byte modified (offset: {before.stop // 2}, byte: {byte})")

    def _search_certificates(self):
        for match in re.finditer(self._cert_pattern, self._data):
            cert_start = match.start()
            rest = self._data[cert_start:]
            efc = re.search(self._seq_pattern, rest)
            if efc is not None:
                pattern_start = efc.start() + cert_start
                cert_end = pattern_start + len(self._seq_pattern) + 518
                offset = pattern_start + 26
                cert_data_src = self._data[cert_start:cert_end]
                before = slice(None, offset - cert_start)
                after = slice(offset - cert_start + 2, None)
                cert_data_rfc = cert_data_src[before] + '05' + cert_data_src[after]
                byte_former = self._data[offset:offset + 2]
                cert = Certificate(cert_data_rfc, offset)
                if cert.is_valid():
                    print(f"Found a certificate (type: {cert.type}, offset: {offset // 2}, byte: {byte_former})")
                    self._certificates.append(cert)

    def _patch_certificates(self, cert_type: CertificateType, byte: str):
        for cert in self._certificates:
            if cert.type == cert_type:
                self._patch(cert.byte_offset, byte)

    def patch(
        self,
        main: Optional[str] = None,
        chain: Optional[str] = None,
        random: bool = False,
    ):
        if random or main:
            byte = choice(self._bytes) if random else main
            self._patch_certificates(CertificateType.MAIN, byte)
        if random or chain:
            byte = choice(self._bytes) if random else chain
            self._patch_certificates(CertificateType.CHAIN, byte)

    def save(self, file_path: str):
        with open(file_path, "wb") as file:
            file.write(bytes.fromhex(self._data))


if __name__ == "__main__":
    patcher = Patcher(args.input_file)
    patcher.patch(args.main, args.chain, args.random)
    patcher.save(args.output_file)

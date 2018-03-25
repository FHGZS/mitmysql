# -*- coding: utf-8 -*-

# Portions are:
#  Code copyright 2010, 2013 PyMySQL contributors
#  Code released under the MIT license
#  https://github.com/PyMySQL/PyMySQL/blob/master/LICENSE

from __future__ import print_function

import errno
from functools import partial
import hashlib
import io
import os
import socket
import struct
import sys
import traceback
import warnings

import pymysql
from pymysql._compat import PY2, range_type, text_type, str_type, JYTHON, IRONPYTHON
from pymysql.connections import *

from pymysql.charset import MBLENGTH, charset_by_name, charset_by_id
from pymysql.constants import CLIENT, COMMAND, CR, FIELD_TYPE, SERVER_STATUS
from pymysql import converters
from pymysql.cursors import Cursor
from pymysql.optionfile import Parser
from pymysql.util import byte2int, int2byte
from pymysql import err

DEBUG = False

class ConnectionWrapper (Connection):

    # difference from original: this returns raw recv result in order that the origin can send it to the client (MITM)
    def _get_server_information(self):
        i = 0

        # read row packet
        raw_data = self._read_packet_raw()
        # with ignoring 4-byte header
        packet = MysqlPacket(raw_data[4:], self.encoding)
        
        packet.check_error()
        data = packet.get_all_data()

        self.protocol_version = byte2int(data[i:i+1])
        i += 1

        server_end = data.find(b'\0', i)
        self.server_version = data[i:server_end].decode('latin1')
        i = server_end + 1

        self.server_thread_id = struct.unpack('<I', data[i:i+4])
        i += 4

        self.salt = data[i:i+8]
        i += 9  # 8 + 1(filler)

        self.server_capabilities = struct.unpack('<H', data[i:i+2])[0]
        i += 2

        if len(data) >= i + 6:
            lang, stat, cap_h, salt_len = struct.unpack('<BHHB', data[i:i+6])
            i += 6
            # TODO: deprecate server_language and server_charset.
            # mysqlclient-python doesn't provide it.
            self.server_language = lang
            try:
                self.server_charset = charset_by_id(lang).name
            except KeyError:
                # unknown collation
                self.server_charset = None

            self.server_status = stat
            if DEBUG: print("server_status: %x" % stat)

            self.server_capabilities |= cap_h << 16
            if DEBUG: print("salt_len:", salt_len)
            salt_len = max(12, salt_len - 9)

        # reserved
        i += 10

        if len(data) >= i + salt_len:
            # salt_len includes auth_plugin_data_part_1 and filler
            self.salt += data[i:i+salt_len]
            i += salt_len

        i+=1
        # AUTH PLUGIN NAME may appear here.
        if self.server_capabilities & CLIENT.PLUGIN_AUTH and len(data) >= i:
            # Due to Bug#59453 the auth-plugin-name is missing the terminating
            # NUL-char in versions prior to 5.5.10 and 5.6.2.
            # ref: https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
            # didn't use version checks as mariadb is corrected and reports
            # earlier than those two.
            server_end = data.find(b'\0', i)
            if server_end < 0: # pragma: no cover - very specific upstream bug
                # not found \0 and last field so take it all
                self._auth_plugin_name = data[i:].decode('latin1')
            else:
                self._auth_plugin_name = data[i:server_end].decode('latin1')
                
        return raw_data

    # This function returns raw packet 
    def _read_packet_raw(self, packet_type=MysqlPacket):
        buff = b''
        while True:
            packet_header = self._read_bytes(4)
            #if DEBUG: dump_packet(packet_header)

            btrl, btrh, packet_number = struct.unpack('<HBB', packet_header)
            bytes_to_read = btrl + (btrh << 16)
            if packet_number != self._next_seq_id:
                self._force_close()
                if packet_number == 0:
                    # MariaDB sends error packet with seqno==0 when shutdown
                    raise err.OperationalError(
                        CR.CR_SERVER_LOST,
                        "Lost connection to MySQL server during query")
                raise err.InternalError(
                    "Packet sequence number wrong - got %d expected %d"
                    % (packet_number, self._next_seq_id))
            self._next_seq_id = (self._next_seq_id + 1) % 256

            recv_data = self._read_bytes(bytes_to_read)
            if DEBUG: dump_packet(recv_data)
            buff += recv_data
            # https://dev.mysql.com/doc/internals/en/sending-more-than-16mbyte.html
            if bytes_to_read == 0xffffff:
                continue
            if bytes_to_read < MAX_PACKET_LEN:
                break

        return packet_header + buff

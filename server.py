#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-
"""
@author: FBK CyberSecurity [ by Sergey Migalin & Andrey Skuratov]
@contact: https://fbkcs.ru
@license Apache License, Version 2.0
Copyright (C) 2018
"""

import signal
import socket
from textwrap import wrap
from time import sleep
import sqlite3
import select
import json
import re
import base64
import argparse

from threading import Thread
from collections import defaultdict

from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users 
    (
    user_id INTEGER NOT NULL PRIMARY KEY, 
    name CHAR(50) NOT NULL, 
    ckey CHAR(3) NOT NULL
    )
"""

GET_MIN_ID = """
SELECT  user_id
FROM    (
        SELECT  1 AS user_id
        ) q1
WHERE   NOT EXISTS
        (
        SELECT  1
        FROM    users
        WHERE   user_id = 1
        )
UNION ALL
SELECT  *
FROM    (
        SELECT  user_id + 1
        FROM    users t
        WHERE   NOT EXISTS
                (
                SELECT  1
                FROM    users ti
                WHERE   ti.user_id = t.user_id + 1
                )
        ORDER BY
                user_id
        LIMIT 1
        ) q2
ORDER BY
        user_id
LIMIT 1;
"""


class ProxyHandler(Thread):
    """
    ThunderProxy handler class
    """
    input_list = []
    channel = {}

    def __init__(self, host, port, name="Proxy Handler", delay=0.000001, buffer_size=4096):
        Thread.__init__(self)
        self.name = name
        self.delay = delay
        self.buffer_size = buffer_size
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)
        self.handlers = defaultdict(lambda: {
            "target_ip": "",
            "target_port": "",
            "socket": None,
            "buffer": None,
            "upstream_buffer": b''
        })

    def run(self):
        self.input_list.append(self.server)
        while 1:
            sleep(self.delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                client = None
                for k, v in self.handlers.items():
                    if v['socket'] == self.s:
                        client = k
                if client is None:
                    self.data = self.s.recv(self.buffer_size)
                    if len(self.data) == 0:
                        self.on_close()
                        break
                    else:
                        self.on_recv()
                else:
                    if self.handlers[client]['buffer'] is None:
                        self.data = self.s.recv(self.buffer_size)
                        if len(self.data) == 0:
                            self.on_close()
                            break
                        else:
                            self.on_recv()

    def on_accept(self):
        clients = self.handlers

        class DataForwarder:
            """
            Data forwarder that emulates socket behavior
            """
            @staticmethod
            def send(data, client):
                clients[client]["buffer"] = data

        forward = DataForwarder()
        clientsock, clientaddr = self.server.accept()
        if forward:
            self.input_list.append(clientsock)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            clientsock.close()

    def on_close(self):
        self.input_list.remove(self.s)
        out = self.channel[self.s]
        self.channel[out].close()
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        data = self.data
        if data == b'\x00GETCLIENTS\n':
            connection = sqlite3.connect('users.db')
            cursor = connection.cursor()
            cursor.execute("SELECT name FROM users")
            clients = {
                'clients': [el[0] for el in cursor.fetchall()]
            }
            self.s.send(bytes(json.dumps(clients), 'utf-8'))
            return

        elif data[0] == 1:
            client_info = str(data[1:], 'utf-8').split(':')
            client = client_info[0]
            self.handlers[client]["socket"] = self.s
            self.handlers[client]["target_ip"] = client_info[1]
            self.handlers[client]["target_port"] = client_info[2]

        elif data[0] == 2:
            client = str(data.split(b':')[1], 'utf-8')
            self.handlers[client]["socket"] = self.s
            self.handlers[client]['target_ip'] = '0.0.0.0'
            self.handlers[client]['target_port'] = '00'
            self.handlers[client]['buffer'] = b'00\n'

        elif data[0] == 3:
            client = None
            for k, v in self.handlers.items():
                if v['socket'] == self.s:
                    client = k
            if client is None:
                return
            self.handlers[client]['socket'] = self.s
            self.channel[self.s].send(data[1:], client=client)


class Resolver(ProxyResolver):
    """
    DNS Resolver
    """

    USER_ID_REGEX = re.compile('\d{2}|$')
    PACKET_REGEX = re.compile('2.{4}(.{2})(.{3})\.(.*)\.')

    def __init__(self, upstream, domain):
        self.DOMAIN_REGEX = re.compile('(.*)' + domain)
        super().__init__(upstream, 53, 5)

    def resolve(self, request, handler):

        domain_request = self.DOMAIN_REGEX.findall(str(request.q.qname))
        type_name = QTYPE[request.q.qtype]

        if not domain_request:
            return super().resolve(request, handler)

        domain_request = domain_request[0]

        packet_type = domain_request[0]
        db = sqlite3.connect('users.db')
        result = ""

        if packet_type == '0':
            cursor = db.cursor()
            cursor.execute(GET_MIN_ID)
            min_id = cursor.fetchone()[0]
            cursor.execute('''INSERT INTO users VALUES (?, ?, 'KEY')''', (min_id, domain_request[8:-1]))
            db.commit()
            result = "{}{}".format(str(min_id).zfill(2), "KEY")
        elif packet_type == '1':
            id = domain_request[-3:-1]
            handler_client = proxy_handler.handlers[id]
            if handler_client['buffer'] is None:
                result = id + 'ND'
            else:
                b64 = base64.b64encode(handler_client['buffer']).decode('utf-8')
                result = "{}{}:{}:{}".format(id,
                                             handler_client['target_ip'],
                                             handler_client['target_port'],
                                             b64)
                proxy_handler.handlers[id]['buffer'] = None
        elif packet_type == '2':
            req = self.PACKET_REGEX.findall(domain_request)
            if req:
                req = req[0]
                handler_client = proxy_handler.handlers[req[0]]
                handler_client['upstream_buffer'] += req[2].encode('utf-8')
                if req[1] != '000':
                    result = '{}{}:OK'.format(req[0], req[1])
                else:
                    handler_client['socket'].send(base64.b64decode(handler_client['upstream_buffer']))
                    handler_client['upstream_buffer'] = b''
                    result = "ENDBLOCK"
            else:
                result = 'Error'

        elif packet_type == '3':
            id = domain_request[-3:-1]
            cursor = db.cursor()
            cursor.execute('''DELETE FROM users WHERE user_id = ?''', (id,))
            db.commit()
            result = "{}REMOVED".format(id)

        reply = request.reply()
        reply.add_answer(RR(
            rname=DNSLabel(str(request.q.qname)),
            rtype=QTYPE.TXT,
            rdata=dns.TXT(wrap(result, 255)),
            ttl=300
        ))

        db.close()

        if reply.rr:
            return reply


def init_db():
    """
    Creates database for users
    """
    connection = sqlite3.connect('users.db')
    try:
        cursor = connection.cursor()
        cursor.execute(CREATE_USERS_TABLE)
        connection.commit()
    finally:
        connection.close()


if __name__ == '__main__':

    print(' ________________               _________         _______________   _________')
    print(' ___/__  __/__/ /_____  ______________/ /______________/ __ \__/ | / //_ ___/')
    print(' _____/ /____/ __ \  / / /_/ __ \/ __  /_/ _ \_/ __/ _/ / / /_/  |/ //____ \ ')
    print(' ____/ /____/ / / / /_/ /_  / / / /_/ / /  __// /  __/ /_/ /_/ /|  / ____/ / ')
    print(' ___/_/____/_/ /_/\__,_/ /_/ /_/\__,_/__\___//_/  __/_____/ /_/ |_/ /_____/  ')

    parser = argparse.ArgumentParser(add_help=True, usage='%(prog)s [options]', description="Thunder DNS server")

    parser.add_argument("-d", "--domain",
                        required=True,
                        help="You domain name")
    parser.add_argument("--buffer_size",
                        required=False,
                        help="IO buffer size, must be BIGGER than in proxy!",
                        default=4096)
    parser.add_argument("--delay_size",
                        required=False,
                        help="IO delay in seconds",
                        default=0.000001)
    parser.add_argument("--dns_port",
                        required=False,
                        help="Set up DNS port. Default 53.",
                        default=53)
    parser.add_argument("--proxy_port",
                        required=False,
                        help="Set up proxy handler port. Default 9091.",
                        default=9091)
    parser.add_argument("--upstream_server",
                        required=False,
                        help="IP of DNS-server, where we will send other requests. Default 8.8.8.8.",
                        default='8.8.8.8')
    args, leftovers = parser.parse_known_args()

    signal.signal(signal.SIGTERM, lambda: exit(0))
    init_db()

    domain = args.domain
    port = args.dns_port
    upstream = args.upstream_server
    proxy_port = args.proxy_port
    delay_size = args.delay_size
    buffer_size = args.buffer_size

    print("Starting DNS server...")
    resolver = Resolver(upstream, domain)
    udp_server = DNSServer(resolver, port=port)
    tcp_server = DNSServer(resolver, port=port, tcp=True)
    proxy_handler = ProxyHandler('', port=proxy_port, delay=delay_size, buffer_size=buffer_size)

    print('DNS server started on port {}, upstream DNS server "{}"'.format(port, upstream))
    udp_server.start_thread()
    tcp_server.start_thread()
    proxy_handler.start()

    try:
        while udp_server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        pass

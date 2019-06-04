#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-
"""
@author: FBK CyberSecurity [ by Sergey Migalin & Andrey Skuratov]
@contact: https://fbkcs.ru
@license Apache License, Version 2.0
Copyright (C) 2018
"""

import socket
import select
import time
import sys
import argparse
import json
import re
import signal


import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

IP_DOMAIN_REGEX = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$|^localhost$|^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
PORT_REGEX = re.compile(r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$")

buffer_size = 4096
delay = 0.000001
clients = {}
client_id = None

SOCKS_VERSION = 5


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass

class SocksProxy(StreamRequestHandler):
    """
    Socks Proxy class
    """
    last_address = 0
    last_port = 0

    def handle(self):
        header = self.connection.recv(2)
        version, count_of_methods = struct.unpack("!BB", header)

        assert version == SOCKS_VERSION
        assert count_of_methods > 0

        methods = self.get_available_methods(count_of_methods)

        if 0 not in set(methods):
            self.server.close_request(self.request)
            return

        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))

        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)

        target_port = struct.unpack('!H', self.connection.recv(2))[0]

        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((args.dns , int(args.dns_port)))
                print('Forwarding data to {}:{}'.format(args.dns, args.dns_port))
                bind_address = remote.getsockname()
                print('Accepting connection from %s:%s' % self.client_address)
                print('Connecting to %s:%s' % (address, target_port))
                remote.send(b'\x02RESET:' + bytes(client_id.zfill(2), 'utf-8') + b':\n')
                time.sleep(1)
                remote.send(b'\x01' + bytes('{}:{}:{}:\n'.format(client_id.zfill(2), str(address), str(target_port)), 'utf-8'))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type,
                                addr, port)   

        except Exception as err:
            print(err)
            reply = self.generate_failed_reply(address_type, 5)

        self.connection.sendall(reply)        

        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    @staticmethod
    def generate_failed_reply(address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    @staticmethod
    def exchange_loop(client, remote):

        while True:
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if (data):
                    if remote.send(b'\x03'+data) <= 0:
                        break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break       


class Forward:
    """
    Forwarder class
    """
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception as e:
            print(e)
            return False


class Proxy:
    """
    Proxy class
    """
    input_list = []
    socket_list = []
    channel = {}

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        print('\nForwarding data to {}:{}'.format(forward_to[0], forward_to[1]))
        global client_id
        global ip
        global port
        forward.send(b'\x02RESET:' + bytes(client_id.zfill(2), 'utf-8') + b':\n')
        time.sleep(1)
        clientsock, clientaddr = self.server.accept()
        if forward:
            print ("Accepting connection from ", clientaddr)
            forward.send(b'\x01' + bytes('{}:{}:{}:\n'.format(client_id.zfill(2), str(ip), str(port)), 'utf-8'))
            self.socket_list.append(clientsock)
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print("Can't establish connection with remote server.")
            print("Closing connection with client side", clientaddr)
            clientsock.close()

    def on_close(self):
        global client_id
        global ip
        global port
        global clients
        print(self.s.getpeername(), "has disconnected")
        clients = {}

        self.socket_list.remove(self.s)
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]

        self.channel[out].close()

        self.channel[self.s].close()

        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):

        if self.s in self.socket_list:
            time.sleep(timeout)
            data = b'\x03' + self.data
        else:
            data = self.data
        self.channel[self.s].send(data)


def handler(signum, frame):
    sys.exit(1)


if __name__ == '__main__':
    print('________________              __________          _________                            ')
    print('___/__  __/__/ /_____  ______________/ /______________/ __ \________________  ______  __')
    print('_____/ /____/ __ \  / / /_  __ \  __  /_  _ \_  ___/_/ /_/ /_/ ___// __ \_  |/_/_  / / /')
    print('____/ /____/ / / / /_/ /_  / / / /_/ / /  __/  /  __/ ____/_/ /   / /_/ /_>  < _  /_/ / ')
    print('___/_/____/_/ /_/\__,_/ /_/ /_/\__,_/__\___//_/  __/_/     /_/    \____//_/|_| _\__, /  ')
    print('                                                                               /____/   ')
    parser = argparse.ArgumentParser(add_help=True, usage='%(prog)s [options]', description="Proxy for Thunder DNS")
    parser.add_argument("--clients", help="Get list of avaliable clients", nargs='?', const=True)
    parser.add_argument("--dns", required=True, help="Address of your DNS server", default=9091)
    parser.add_argument("--dns_port", default="9091", help="Port to connect to your DNS server")
    parser.add_argument("--target", help="Address where you want to connect", default='')
    parser.add_argument("--target_port", help="Port to connecnt to target IP", default='')
    parser.add_argument("--client", help="Client id", default='')
    parser.add_argument("--send_timeout", help="Timeout in seconds before sending message", default=0.2)
    parser.add_argument("--localport", help="Local port to connect application", default=9090)
    parser.add_argument("--socks5", help="Use sock5 mode", nargs='?', const=True)
    args, leftovers = parser.parse_known_args()

    if not IP_DOMAIN_REGEX.match(args.dns):
        print('Invalid DNS')
        exit(0)

    if not PORT_REGEX.match(args.dns_port):
        print('Invalid DNS port')
        exit(0)

    forward_to = (args.dns, int(args.dns_port))

    try:
        timeout = float(args.send_timeout)
    except ValueError:
        print('Timeout value must be int or float')
        exit(0)

    if args.clients is not None:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.connect((args.dns, int(args.dns_port)))
        soc.send(b'\x00GETCLIENTS\n')
        clients = json.loads(soc.recv(buffer_size).decode('utf-8'))
        print('Clients available:')
        for el in range (0, len(clients['clients'])):
            print(str(el + 1) + '. ' + clients['clients'][el])
        exit(0)

    if not IP_DOMAIN_REGEX.match(args.target) and not args.socks5:
        print('Invalid TARGET')
        exit(0)

    if not args.socks5:
    	ip = args.target

    if not PORT_REGEX.match(args.target_port) and not args.socks5:
        print('Invalid TARGET port')
        exit(0)

    if not args.socks5:
    	port = int(args.target_port)

    if not re.match(r'^[a-zA-Z0-9]{1,100}$', args.client):
        print('Invalid id')
        exit(0)
    try:
        int(args.client)
        client_id = args.client
    except ValueError:
        print("Client id must be integer")
        exit(0)

    try:
        if not (0 < int(args.localport) < 65535):
            print('Invalid port number!')
            exit(0)
    except (TypeError, ValueError):
        print('Parameter localport must be possitive integer')
        exit(0)

    signal.signal(signal.SIGTERM, handler)

    print('All right! After establishing connection, we will work with client ', client_id)

    if args.socks5:
        print('SOCKS5 mode enabled!')
        try:
            with ThreadingTCPServer(('127.0.0.1', int(args.localport)), SocksProxy) as server:
                server.serve_forever()
        except KeyboardInterrupt:
            print("Ctrl C - Stopping server")
            server.shutdown()     
    else:   
        server = Proxy('', int(args.localport) )
        try:
            server.main_loop()
        except KeyboardInterrupt:
            print("Ctrl C - Stopping server")
            sys.exit(1)
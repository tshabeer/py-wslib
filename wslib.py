# -*- coding: utf8 -*-
"""
Copyright (C) 2012 Roderick Baier <roderick.baier@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import socket
import urlparse
import hashlib
import base64
import ctypes
import struct
import array
import select
from random import Random
from threading import Thread


__all__ = ['WebSocket', 'WebSocketServer', 'WebSocketHandler']


STATE_CONNECTING = 0
STATE_OPEN = 1
STATE_CLOSING = 2
STATE_CLOSED = 3

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA
OPCODES = [OPCODE_TEXT,
           OPCODE_BINARY,
           OPCODE_CLOSE,
           OPCODE_PING,
           OPCODE_PONG]


class WebSocketError(Exception): pass


class BaseWebSocket(object):
    
    _ready_state = STATE_CONNECTING
    _frame_reader = None
    
    def __init__(self, handler, mask):
        self.handler = handler
        self.mask = mask
    
    def _send_raw(self, data):
        self.socket.sendall(str(data))
    
    def _send_close_handshake(self):
        if self._ready_state == STATE_OPEN:
            self._ready_state = STATE_CLOSING
            # TODO
        else:
            print "error send_close_handshake"
    
    def close(self):
        if self._ready_state > STATE_CONNECTING:
            self._ready_state = STATE_CLOSING
            self._send_close_handshake()
            self._frame_reader.stop()
            self.socket.close()
        self._ready_state = STATE_CLOSED


class WebSocket(BaseWebSocket):
    
    header_fields = {}
    
    def __init__(self, url, handler, protocol=None, mask=True):
        BaseWebSocket.__init__(self, handler, mask)
        self.handshake = ClientHandshake(url)
        print "handshake:", self.handshake
        self.url = url
    
    def add_header_field(self, key, value):
        self.header_fields[key.strip()] = value.strip()
    
    def connect(self):
        self._create_socket()
        self._send_raw(self.handshake)
        headers = self._read_handshake()
        print headers
        if headers['Sec-WebSocket-Accept'] != self.handshake.key_accept(self.handshake.nonce):
            raise Exception("accept key error")
        self._frame_reader = FrameReader(self.socket, self.handler.onmessage)
        self._frame_reader.start()
        self._ready_state = STATE_OPEN
        self.handler.onopen(None)
    
    def _read_handshake(self):
        handshake = self.socket.recv(4096)
        if handshake:
            print handshake
            lines = handshake.split('\n')
            status = lines[0].split()
            if status[1] != "101":
                raise Exception("upgrade error")
            headers = {}
            for line in lines[1:]:
                if line.strip() == "":
                    break
                line = line.strip().split(": ", 1)
                headers[line[0]] = line[1]
            print "headers:", headers
            return headers
        else:
            raise WebSocketError("handshake failed")
    
    def send(self, message):
        print "sending:", message
        if self._ready_state == STATE_OPEN:
            self._send_raw(TextFrame(message))
        else:
            print "error: send_text"
    
    def send_binary(self, data):
        print "sending:", data
        if self._ready_state == STATE_OPEN:
            self._send_raw(BinaryFrame(data))
        else:
            print "error: send_binary"
    
    def _create_socket(self):
        urlparse.uses_netloc.append("ws")
        urlparts = urlparse.urlparse(self.url)
        host = urlparts.hostname
        port = urlparts.port
        if not port:
            port = 80
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))


class ServerWebSocket(BaseWebSocket):
    
    def __init__(self, socket, handler, mask=True):
        BaseWebSocket.__init__(self, handler, mask)
        print "creating ServerWebSocket instance"
        self.socket = socket
        request, headers = self._read_handshake()
        handshake = ServerHandshake(client_key=headers['Sec-WebSocket-Key'])
        self._send_raw(handshake)
        self._frame_reader = FrameReader(self.socket, handler.onmessage)
        self._frame_reader.start()
    
    def _read_handshake(self):
        handshake = self.socket.recv(4096)
        print "received handshake:", handshake
        lines = handshake.split('\n')
        request = lines[0].split()
        headers = {}
        for line in lines[1:]:
            if line.strip() == "":
                break
            line = line.strip().split(": ", 1)
            headers[line[0]] = line[1]
        print "headers:", headers
        if not "Upgrade" in headers and headers['Upgrade'] is not "websocket":
            raise WebSocketError("not upgrade")
        return request[1], headers
    
    def send(self, data):
        self._send_raw(data)


class Handshake(object):
    
    def __init__(self, headers, protocols, extensions):
        self.headers = headers
        self.protocols = protocols
        self.extensions = extensions
    
    def key_accept(self, key):
        hash = hashlib.sha1(key + GUID).digest()
        return base64.b64encode(hash)


class ClientHandshake(Handshake):
    
    def __init__(self, url, headers={}, protocols={}, extensions={}, origin=None):
        Handshake.__init__(self, headers, protocols, extensions)
        urlparse.uses_netloc.append("ws")
        url_parts = urlparse.urlparse(url)
        self.host = url_parts.hostname
        self.port = url_parts.port
        self.origin = url_parts.hostname
        self.resource = url_parts.path
        self.origin = origin
        self.nonce = base64.b64encode(os.urandom(16))
    
    def __repr__(self):
        handshake = "GET " + self.resource + " HTTP/1.1\r\n" + \
                    "Host: " + self.host + "\r\n" + \
                    "Upgrade: websocket\r\n" + \
                    "Connection: Upgrade\r\n" + \
                    "Sec-WebSocket-Key: " + self.nonce + "\r\n"
        if self.origin:
            "Origin:" + self.origin + "\r\n"
        if self.protocols:
            if type(self.protocols) is list:
                handshake += "Sec-WebSocket-Protocol: %s\r\n" % ', '.join(self.protocols)
            else:
                handshake += "Sec-WebSocket-Protocol: %s\r\n" % self.protocols.strip()
        if self.extensions:
            pass # TODO
        if self.headers:
            for key in self.headers:
                handshake += "%s: %s\r\n" % (key, self.headers[key].strip())
        handshake += "\r\n"
        handshake = handshake.encode('ascii')
        return handshake


class ServerHandshake(Handshake):
    
    def __init__(self, client_key=None, client_protocols={}, headers={}, protocols={}, extensions={}):
        Handshake.__init__(self, headers, protocols, extensions)
        self.client_key = client_key
        self.client_protocols = client_protocols
    
    def __repr__(self):
        handshake = "HTTP/1.1 101 Switching Protocols\r\n" + \
                    "Upgrade: websocket\r\n" + \
                    "Connection: Upgrade\r\n" + \
                    "Sec-WebSocket-Accept: " + self.key_accept(self.client_key) + "\r\n"
        sub_protocol = self.get_sub_protocol()
        if sub_protocol:
            handshake += "Sec-WebSocket-Protocol: " + self.get_sub_protocol() + "\r\n"
        handshake += "\r\n"
        return handshake
    
    def get_sub_protocol(self):
        """Choose preferred sub protocol"""
        return None


class Frame(object):
    
    def __init__(self, opcode, data, masking):
        self.opcode = opcode
        self.data = data
        self.masking = masking
    
    def __repr__(self):
        fin = 0x80
        length = len(self.data)
        frame = struct.pack("!B", fin | self.opcode)
        if length < 126:
            if self.masking:
                length = 0x80 | length
            frame += struct.pack("!B", length)
        elif length <= 65535:
            len_field = 126
            if self.masking:
                len_field = 0x80 | len_field
            frame += struct.pack("!BH", len_field, length)
        else:
            len_field = 127
            if self.masking:
                len_field = 0x80 | len_field
            frame += struct.pack("!BQ", len_field, length)
        if self.masking:
            masking_key = array.array("B", os.urandom(4))
            frame += masking_key.tostring()
            data = array.array("B", self.data)
            for i in range(len(data)):
                data[i] = data[i] ^ masking_key[i % 4]
            frame += data.tostring()
        else:
            frame += self.data
        return frame


class TextFrame(Frame):
    
    def __init__(self, message, masking=True):
        Frame.__init__(self, OPCODE_TEXT, message, masking)


class BinaryFrame(Frame):
    
    def __init__(self, data, masking=True):
        Frame.__init__(self, OPCODE_BINARY, data, masking)


class CloseFrame(Frame):
    
    def __init__(self):
        Frame.__init__(self, OPCODE_CLOSE, '', False)


class PingFrame(Frame):
    
    def __init__(self):
        Frame.__init__(self, OPCODE_PING, '', False)


class PongFrame(Frame):
    
    def __init__(self):
        Frame.__init__(self, OPCODE_PONG, '', False)


class FrameReader(Thread):
    
    def __init__(self, socket, onmessage):
        Thread.__init__(self)
        self.socket = socket
        self.onmessage = onmessage
        self.running = True
    
    def run(self):
        self.socket.setblocking(0)
        while self.running:
            try:
                ready = select.select([self.socket], [], [], 1)
            except:
                print "socket closed, stopping FrameReader"
                break
            if ready[0]:
                data = self.socket.recv(2)
                print "data", data
                if data == '':
                    print "connection lost"
                    break
                header, length = struct.unpack("!BB", data)
                opcode = header & 0xf
                if not opcode in OPCODES:
                    raise WebSocketError("unknown or unsupported opcode")
                reserved = header & 0x70
                masked = length & 0x80
                length = length & 0x7f
                if length < 126:
                    payload_length = length
                elif length == 126:
                    data = self.socket.recv(2)
                    payload_length = struct.unpack("!H", data)[0]
                elif length == 127:
                    data = self.socket.recv(8)
                    payload_length = struct.unpack("!Q", data)[0]
                if masked:
                    data = self.socket.recv(4)
                    masking_key = struct.unpack("!BBBB", data)
                data = self.socket.recv(payload_length)
                if masked:
                    data = array.array("B", data)
                    for i in range(len(data)):
                        data[i] = data[i] ^ masking_key[i % 4]
                    self.onmessage(data.tostring())
                else:
                    self.onmessage(data)
        print "FrameReader: stopped"
    
    def stop(self):
        self.running = False
        print "FrameReader: stopping"


class WebSocketServer(object):
    
    def __init__(self, host, port, handler, origins=[]):
        self.host = host
        self.port = port
        self.handler = handler
        self.origins = origins
    
    def onconnect(self, client):
        sub_protocol = self.choose_sub_protocol(client.sub_protocols)
        if sub_protocol:
            client.accept(sub_protocol)
        else:
            client.disconnect()
    
    def serve_forever(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        #server_socket.setblocking(0)
        server_socket.bind(('', self.port))
        server_socket.listen(128)
        while True:
            client_socket, client_address = server_socket.accept()
            ServerWebSocket(client_socket, self.handler)
    
    def choose_sub_protocol(sub_protocols=None):
        return None


class WebSocketHandler(object):
    
    def onopen(self, protocol):
        pass
    
    def onmessage(self, message):
        pass
    
    def onclose(self):
        pass

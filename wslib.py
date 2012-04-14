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
import time
import ssl
from random import Random
from threading import Thread


__all__ = ['WebSocket', 'WebSocketServer', 'WebSocketHandler',
           'WebSocketRequestHandler']


urlparse.uses_netloc.append('ws')
urlparse.uses_netloc.append('wss')


WEBSOCKET_VERSION = 13

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

STATE_CONNECTING = 0
STATE_OPEN = 1
STATE_CLOSING = 2
STATE_CLOSED = 3

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

class WebSocketHandshakeError(Exception): pass

class WebSocketProtocolError(Exception): pass

class WebSocketClosedError(Exception): pass


class BaseWebSocket(object):
    
    _ready_state = STATE_CONNECTING
    _socket = None
    _secure = False
    _frame_reader = None
    _last_ping = 0
    
    def __init__(self, handler, mask):
        self.handler = handler
        self.handler.websocket = self
        self.mask = mask
    
    def _set_open(self):
        self._socket.setblocking(0)
        self._frame_reader = FrameReader(self)
        self._frame_reader.start()
        self._ready_state = STATE_OPEN
    
    def is_open(self):
        return self._ready_state == STATE_OPEN
    
    def is_closing(self):
        return self._ready_state == STATE_CLOSING
    
    def ready(self):
        try:
            ready = select.select([self._socket], [], [], 1)
            return True if ready[0] else False
        except:
            raise WebSocketClosedError("socket closed")
    
    def read(self, size):
        return self._socket.recv(size)
    
    def _send_raw(self, data):
        self._socket.sendall(str(data))
    
    def send(self, message):
        if self.is_open():
            self._send_raw(TextFrame(message))
        else:
            raise WebSocketClosedError("can't send message: connection not open")
    
    def send_binary(self, data):
        if self.is_open():
            self._send_raw(BinaryFrame(data))
        else:
            raise WebSocketClosedError("can't send message: connection not open")
    
    def send_ping(self):
        if self.is_open():
            self._send_raw(PingFrame())
            self._last_ping = time.time()
        else:
            raise WebSocketClosedError("can't send ping: connection not open")
    
    def _send_pong(self):
        self._send_raw(PongFrame())
    
    def _ping_timeout(self):
        pass
    
    def close(self):
        if self.is_open():
            self._ready_state = STATE_CLOSING
            self._send_raw(CloseFrame())
        elif self.is_closing():
            self._ready_state = STATE_CLOSED
            self._frame_reader.stop()
            self._socket.close()


class WebSocket(BaseWebSocket):
    
    header_fields = {}
    
    def __init__(self, url, handler, protocol=None, mask=True):
        BaseWebSocket.__init__(self, handler, mask)
        self.url = url
    
    def add_header(self, key, value):
        self.header_fields[key.strip()] = value.strip()
    
    def connect(self):
        self._create_socket()
        handshake = ClientHandshake(self.url)
        self._send_raw(handshake)
        self.server_headers = self._read_handshake()
        if self.server_headers['Sec-WebSocket-Accept'] != handshake.key_accept(handshake.nonce):
            self.websocket.close()
            raise WebSocketHandshakeError("Sec-WebSocket-Key does not match with Sec-WebSocket-Accept")
        self._set_open()
        self.handler.onopen(None)
    
    def _read_handshake(self):
        handshake = self.read(4096)
        if handshake:
            lines = handshake.split('\n')
            status = lines[0].split()
            if status[1] != '101':
                raise WebSocketHandshakeError("upgrade failed")
            headers = {}
            for line in lines[1:]:
                if line.strip() == "":
                    break
                line = line.strip().split(": ", 1)
                headers[line[0]] = line[1]
            return headers
        else:
            raise WebSocketHandshakeError("handshake failed")
    
    def _create_socket(self):
        urlparts = urlparse.urlparse(self.url)
        if urlparts.scheme == 'ws':
            default_port = 80
        elif urlparts.scheme == 'wss':
            default_port = 443
            self._secure = True
        else:
            raise WebSocketError("invalid url")
        port = urlparts.port
        if not port:
            port = default_port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((urlparts.hostname, port))


class ServerWebSocket(BaseWebSocket):
    
    def __init__(self, socket, handler, secure, mask=True):
        BaseWebSocket.__init__(self, handler, mask)
        self._socket = socket
        try:
            self._read_handshake()
        except WebSocketHandshakeError, err:
            self._reject(message=err)
        else:
            request = _Request(self.query, self.request_protocols,
                               self.request_headers, self._accept,
                               self._reject)
            self.handler.onrequest(request)
    
    def _accept(self, protocol=None):
        handshake = ServerHandshake(self.key, protocol)
        self._send_raw(handshake)
        self._set_open()
    
    def _reject(self, code=404, message="Not Found", headers=None):
        data = "HTTP/1.1 %s %s\r\n" % (code, message)
        if headers:
            for (header, value) in headers:
                data += "%s: %s\r\n" % (header, value)
        data += "\r\n"
        self._send_raw(data)
        self._socket.close()
        self._ready_state = STATE_CLOSED
    
    def _read_handshake(self):
        handshake = self.read(4096)
        lines = handshake.split('\n')
        self.query = lines[0].split()[1]
        self.request_headers = {}
        for line in lines[1:]:
            if line.strip() == "":
                break
            line = line.strip().split(": ", 1)
            self.request_headers[line[0]] = line[1]
        if (not "Upgrade" in self.request_headers
        and self.request_headers['Upgrade'] is not 'websocket'):
            # TODO reject
            raise WebSocketHandshakeError("upgrade header missing")
        self.request_protocols = []
        if 'Sec-WebSocket-Protocol' in self.request_headers:
            protocol_str = headers['Sec-WebSocket-Protocol']
            del self.request_headers['Sec-WebSocket-Protocol']
            for protocol in filter(None, protocol_str.split(",")):
                self.request_protocols.append(protocol.strip())
        if 'Sec-WebSocket-Key' in self.request_headers:
            self.key = self.request_headers['Sec-WebSocket-Key']
            del self.request_headers['Sec-WebSocket-Key']
        else:
            raise WebSocketHandshakeError("client key missing")
        if 'Sec-WebSocket-Version' in self.request_headers:
            if self.request_headers['Sec-WebSocket-Version'] != WEBSOCKET_VERSION:
                # TODO reject
                raise WebSocketHandshakeError("wrong protocol version")


class _Request(object):
    
    def __init__(self, query, protocols, headers, accept, reject):
        self.query = query
        self.protocols = protocols
        self.headers = headers
        self.accept = accept
        self.reject = reject
    
    def accept(self, protocol=None):
        self.accept()
    
    def reject(self):
        self.reject()


class Handshake(object):
    
    def __init__(self, headers, extensions):
        self.headers = headers
        self.extensions = extensions
    
    def key_accept(self, key):
        hash = hashlib.sha1(key + GUID).digest()
        return base64.b64encode(hash)


class ClientHandshake(Handshake):
    
    def __init__(self, url, headers={}, protocols={}, extensions={}, origin=None):
        Handshake.__init__(self, headers, extensions)
        self.protocols = protocols
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
                handshake += "Sec-WebSocket-Protocol: %s\r\n" % ', '.join(filter(None, self.protocols))
            else:
                handshake += "Sec-WebSocket-Protocol: %s\r\n" % self.protocols.strip()
        if self.headers:
            for key in self.headers:
                handshake += "%s: %s\r\n" % (key, self.headers[key].strip())
        handshake += "\r\n"
        handshake = handshake.encode('ascii')
        return handshake


class ServerHandshake(Handshake):
    
    def __init__(self, client_key, protocol, headers={}, extensions={}):
        Handshake.__init__(self, headers, extensions)
        self.client_key = client_key
        self.protocol = protocol
    
    def __repr__(self):
        handshake = "HTTP/1.1 101 Switching Protocols\r\n" + \
                    "Upgrade: websocket\r\n" + \
                    "Connection: Upgrade\r\n" + \
                    "Sec-WebSocket-Accept: " + self.key_accept(self.client_key) + "\r\n"
        if self.protocol:
            handshake += "Sec-WebSocket-Protocol: " + self.protocol + "\r\n"
        handshake += "\r\n"
        return handshake


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
    
    def __init__(self, websocket):
        Thread.__init__(self)
        self.websocket = websocket
        self.running = True
    
    def run(self):
        while self.running:
            try:
                if self.websocket.ready():
                    data = self.websocket.read(2)
                    if data == '':
                        print "connection lost" # TODO
                        break
                    header, length = struct.unpack("!BB", data)
                    opcode = header & 0xf
                    if not opcode in OPCODES:
                        raise WebSocketProtocolError("unknown opcode")
                    if opcode == OPCODE_PING:
                        self.websocket._send_pong()
                        continue
                    elif opcode == OPCODE_PONG:
                        print "received pong after %s seconds" % \
                              (time.time() - self.websocket._last_ping) # TODO
                        continue
                    elif opcode == OPCODE_CLOSE:
                        self.websocket.close()
                        continue
                    reserved = header & 0x70
                    masked = length & 0x80
                    length = length & 0x7f
                    if length < 126:
                        payload_length = length
                    elif length == 126:
                        data = self.websocket.read(2)
                        payload_length = struct.unpack("!H", data)[0]
                    elif length == 127:
                        data = self.websocket.read(8)
                        payload_length = struct.unpack("!Q", data)[0]
                    if masked:
                        data = self.websocket.read(4)
                        masking_key = struct.unpack("!BBBB", data)
                    data = self.websocket.read(payload_length)
                    if masked:
                        data = array.array("B", data)
                        for i in range(len(data)):
                            data[i] = data[i] ^ masking_key[i % 4]
                        self.websocket.handler.onmessage(data.tostring())
                    else:
                        self.websocket.handler.onmessage(data)
            except:
                break
        self.websocket.close()
    
    def stop(self):
        self.running = False


class WebSocketServer(object):
    
    def __init__(self, host, port, handler, secure=False, origins=[]):
        self.host = host
        self.port = port
        self.handler = handler
        self.secure = secure
        self.origins = origins
    
    def serve_forever(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        server_socket.bind(('', self.port))
        server_socket.listen(128)
        while True:
            client_socket, client_address = server_socket.accept()
            ServerWebSocket(client_socket, self.handler, self.secure)


class WebSocketHandler(object):
    
    websocket = None
    
    def onopen(self, protocol):
        pass
    
    def onmessage(self, message):
        pass
    
    def onclose(self):
        pass


class WebSocketRequestHandler(WebSocketHandler):
    
    def onrequest(self, request):
        request.accept()

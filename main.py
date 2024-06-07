#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (C) 2024 Alice Lange

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License Version 2 as published by
the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/gpl-2.0.html>.
"""

import socket
import threading
import logging
from typing import NoReturn, Union, Dict
import mimetypes
import os

class Webserver:
    def __init__(self, host_address: str = '127.0.0.1', port: int = 80) -> None:
        self.host_address = host_address
        self.port = port

        mimetypes.init()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host_address, port))
        
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info(f'Server initialized on {host_address}:{port}')

    def _http_constructor(self, status: str, headers: Dict[str, str], body: bytes) -> bytes:
        http_response: str = f'{status}\r\n'

        for key, value in headers.items():
            http_response += f'{key}: {value}\r\n'
        http_response += '\r\n'

        return http_response.encode('utf-8') + body

    def _http_parser(self, binary: bytes) -> Union[None, Dict[str, Union[str, Dict[str, str], bytes]]]:
        try:
            http_req = binary.split(b'\r\n\r\n')
            headers_part = http_req[0].decode('utf-8')
            body_part = b'' if len(http_req) == 1 else http_req[1]

            logging.info(f'HTTP request received:\n{headers_part}\n{body_part}')
        except Exception as exception:
            logging.error('Error decoding HTTP request', exc_info=True)
            return None

        # Split headers part into lines
        lines = headers_part.split('\r\n')
        if not lines:
            return None
        
        # Parse request line
        request_line = lines[0].split(' ')
        if len(request_line) != 3:
            return None
        method, path, http_version = request_line

        # Parse headers
        headers = {}
        for line in lines[1:]:
            key, value = line.split(': ', 1)
            headers[key] = value
        
        # Create dictionary
        request_dict = {
            'method': method,
            'path': path,
            'http_version': http_version,
            'headers': headers,
            'body': body_part
        }
        
        return request_dict

    def _handle_request(self, request: Dict[str, Union[str, Dict[str, str], bytes]]) -> bytes:
        method = request['method']
        path = request['path']
        if method == 'GET':
            file_path = path.lstrip('/')
            if file_path == '':
                file_path = 'index.html'
            try:
                with open(file_path, 'rb') as f:
                    body = f.read()
                status = 'HTTP/1.1 200 OK'
                headers = {'Content-Type': mimetypes.types_map['.' + file_path.split('.')[-1]], 'Content-Length': str(len(body))}
                
            except FileNotFoundError:
                status = 'HTTP/1.1 404 Not Found'
                body = b'404 Not Found'
                headers = {'Content-Type': 'text/plain', 'Content-Length': str(len(body))}
        else:
            status = 'HTTP/1.1 405 Method Not Allowed'
            body = b'405 Method Not Allowed'
            headers = {'Content-Type': 'text/plain', 'Content-Length': str(len(body))}

        return self._http_constructor(status, headers, body)

    def _connection_handler(self, client_socket: socket.socket) -> NoReturn:
        logging.info('Client connected')
        try:
            while True:
                binary: bytes = client_socket.recv(1024)
                if binary:
                    parsed_request = self._http_parser(binary)
                    if parsed_request:
                        logging.info(f'Parsed request: {parsed_request}')
                        response = self._handle_request(parsed_request)
                        client_socket.sendall(response)
                    else:
                        break
                else:
                    break
        except Exception as exception:
            logging.error('Error handling client connection', exc_info=True)
        finally:
            client_socket.close()
            logging.info('Client disconnected')

    def _listener(self) -> NoReturn:
        self.sock.listen(5)
        logging.info('Server listening for connections')
        while True:
            try:
                client_socket, client_address = self.sock.accept()
                logging.info(f'Connection accepted from {client_address}')
                threading.Thread(target=self._connection_handler, args=(client_socket,)).start()
            except Exception as exception:
                logging.error('Error accepting connections', exc_info=True)

    def start(self) -> NoReturn:
        try:
            self._listener()
        except KeyboardInterrupt:
            logging.info('Server shutting down')
        finally:
            self.sock.close()

if __name__ == "__main__":
    server = Webserver(port=5001)
    server.start()

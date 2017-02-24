#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os.path
import unittest
import socket
import json
import datetime
import time
from email.utils import formatdate
from httpserver import BaseServer
from httpserver import HttpResponse


class Test_serv(unittest.TestCase):

    def setUp(self):
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        self.app = BaseServer('127.0.0.1', 8080)

    def tearDown(self):
        pass

    def test_method_headers(self):
        str_headers = "Host: www.site.ru\r\n"
        str_headers += "Referer: http://www.site.ru/index.html\r\n"
        str_headers += "User-Agent: Mozilla/4.0\r\n"
        str_headers += "Accept-Language: en-us\r\n"
        str_headers += "Connection: Keep-Alive\r\n"
        str_headers += "\r\n"
        headers = self.app.find_headers(str_headers[:-4])
        self.assertEqual(headers["connection"], "Keep-Alive")

    def test_method_headers_2(self):
        params = self.app.get_method("127.0.01:8080/search?k=v&k1=v1")
        self.assertEqual(params["k"], "v")
        self.assertEqual(params["k1"], "v1")

    def test_get_method(self):
        self.get("key=value&key&ley=va=lue&=val&&kk")
        self.get("key=value&key=ley")
        self.get("key=value&key")
        self.get("key=value&=")
        self.get("&&&&===")

    def get(self, pairs):
        # Equals wits  key-value pairs in GET
        # httpbin and serv
        #
        link = "httpbin.org/get?" + pairs
        params = self.app.get_method(link)
        data_serv = params
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = ("httpbin.org", 80)
        sock.connect(addr)
        CRLF = b"\r\n"
        q = b"GET http://httpbin.org/get?" + \
            pairs.encode() + b" HTTP/1.1" + CRLF
        q += b"User-Agent: Mozilla/4.0" + CRLF
        q += b"Host: httpbin.org" + CRLF
        q += b"Connection: Close" + CRLF
        q += CRLF
        sock.send(q)
        response = sock.recv(65535)
        sock.close()
        status = re.search(b"HTTP.*? (\d+) ", response[:16])
        status_code = status.group(1).decode()
        start, end = re.search(b"\r\n\r\n", response).span()
        headers = self.app.find_headers(
            response[:start].decode().split("\r\n", 1)[1])
        data_json = json.loads(response[end:].decode())

        self.assertEqual(status_code, "200")
        self.assertEqual(data_serv, data_json["args"])

    def post(self, pairs):
        # Equals wits  key-value pairs application/x-www-form-urlencoded
        # httpbin and serv
        #
        par = pairs.encode()
        length = str(len(par))
        headers = {}
        headers["content-type"] = "application/x-www-form-urlencoded"
        params = self.app.post_method(par, headers)
        data_serv, p_body, p_files = params
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = ("httpbin.org", 80)
        sock.connect(addr)
        CRLF = b"\r\n"
        q = b"POST http://httpbin.org/post" + b" HTTP/1.1" + CRLF
        q += b"User-Agent: Mozilla/4.0" + CRLF
        q += b"Host: httpbin.org" + CRLF
        q += b"Content-Length: " + length.encode() + CRLF
        q += b"Content-Type: application/x-www-form-urlencoded" + CRLF
        q += b"Connection: Close" + CRLF
        q += CRLF
        q += par
        sock.send(q)
        response = sock.recv(65535)
        sock.close()
        status = re.search(b"HTTP.*? (\d+) ", response[:16])
        status_code = status.group(1).decode()
        start, end = re.search(b"\r\n\r\n", response).span()
        headers = self.app.find_headers(
            response[:start].decode().split("\r\n", 1)[1])
        data_json = json.loads(response[end:].decode())

        self.assertEqual(data_serv, data_json["form"])
        self.assertEqual(status_code, "200")

    def test_post_method(self):
        self.post("key=value&key&ley=va=lue&=val&&kk")
        self.post("key=value&key=ley")
        self.post("key=value&key")
        self.post("key=value&=")
        self.post("&&&&===")

    def test_path_finder(self):
        link = "https://127.0.0.1:8080/search?q=pasha+volia"
        path = self.app.pathfinder(link)
        self.assertEqual(path, "/search")

        link = "http://yandex.com/search?q=pasha+volia"
        path = self.app.pathfinder(link)
        self.assertEqual(path, "/search")


if __name__ == '__main__':
    unittest.main()

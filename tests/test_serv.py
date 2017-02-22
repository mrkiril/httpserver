#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os.path
import unittest
import socket
import json
from httpserver import BaseServer


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
        text = "GET http://www.google.com.ua HTTP/1.0\r\n"
        text += "Host: www.site.ru\r\n"
        text += "Referer: http://www.site.ru/index.html\r\n"
        text += "User-Agent: Mozilla/4.0\r\n"
        text += "Accept-Language: en-us\r\n"
        text += "Connection: Keep-Alive\r\n"
        text += "Content-Length: 8\r\n"
        text += "\r\n"
        text += "hh=ppppp"
        end = re.search("\r\n\r\n", text).span()[1]
        params = self.app.content_length2(text, 8, end)
        self.assertEqual(params, text)



    def test_post_method(self):
        # Equals wits  key-value pairs application/x-www-form-urlencoded
        # httpbin and serv
        #
        par = b"key=value&key&ley=va=lue&=val&&kk"
        headers = {}
        headers["content-type"] = "application/x-www-form-urlencoded"
        params = self.app.post_method(par, headers)
        data_serv, p_body, p_files = params
        

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = ("httpbin.org", 80)
        sock.connect(addr)
        CRLF = b"\r\n"
        q = b"GET http://httpbin.org/get?"+par+ b" HTTP/1.1" + CRLF
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
        self.assertEqual(status_code, "200")             
        headers = self.app.find_headers(response[:start].decode().split("\r\n", 1)[1])
        data_json = json.loads(response[end:].decode())


        self.assertEqual(data_serv, data_json["args"])

    def test_path_finder(self):
        link = "https://127.0.0.1:8080/search?q=pasha+volia"
        path = self.app.pathfinder(link)
        self.assertEqual(path, "/search")

        link = "http://yandex.com/search?q=pasha+volia"
        path = self.app.pathfinder(link)
        self.assertEqual(path, "/search")


    











if __name__ == '__main__':
    unittest.main()

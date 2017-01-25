import sys
import datetime
import time
import re
import socket
import base64
import json
import mimetypes
import os.path
import logging
import random
import string
import math
import hashlib
from httpclient import HttpClient
import unittest
from httpserver import HttpErrors
from httpserver import HtCode
from httpserver import ZeroAnswer
from httpserver import HttpRequest
from httpserver import HttpResponse
from httpserver import BaseServer


class Test_serv(unittest.TestCase):

    def setUp(self):
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        self.app = BaseServer('127.0.0.1', 8080)

    def tearDown(self):
        pass

    def test_method_headers(self):
        str_headers = "GET http://www.site.ru/news.html HTTP/1.0\r\n"
        str_headers += "Host: www.site.ru\r\n"
        str_headers += "Referer: http://www.site.ru/index.html\r\n"
        str_headers += "User-Agent: Mozilla/4.0 "\
            "(compatible; MSIE5.01; Windows NT)\r\n"
        str_headers += "Accept-Language: en-us\r\n"
        str_headers += "Connection: Keep-Alive\r\n"
        str_headers += "\r\n"

        headers = BaseServer.find_headers(self.app, str_headers[:-4])

        # перевірка на успішність запиту
        self.assertEqual(headers["Connection"], "Keep-Alive")

    def test_method_headers(self):
        params = BaseServer.get(self.app, "127.0.01:8080/search?k=v&k1=v1")
        self.assertEqual(params["k"], "v")
        self.assertEqual(params["k1"], "v1")

    def test_cont_len(self):
        text = "GET http://www.site.ru/news.html HTTP/1.0\r\n"
        text += "Host: www.site.ru\r\n"
        text += "Referer: http://www.site.ru/index.html\r\n"
        text += "User-Agent: Mozilla/4.0 (compatible; "\
            "MSIE5.01; Windows NT)\r\n"
        text += "Accept-Language: en-us\r\n"
        text += "Connection: Keep-Alive\r\n"
        text += "Content-Length: 8\r\n"
        text += "\r\n"
        text += "hh=ppppp"

        end = re.search("\r\n\r\n", text).span()[1]

        params = BaseServer.content_length2(self.app, text, 8, end)
        self.assertEqual(params, text)

    def test_path_finder(self):
        # (https?://)?[^/]*(.*)
        link = "https://127.0.0.1:8080/search?q=pasha+volia"
        path = BaseServer.pathfinder(self.app, link)
        self.assertEqual(path, "/search")

        link = "http://yandex.com/search?q=pasha+volia"
        path = BaseServer.pathfinder(self.app, link)
        self.assertEqual(path, "/search")


if __name__ == '__main__':
    unittest.main()

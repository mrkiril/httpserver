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
#sys.path.append(os.path.abspath(os.path.join(os.path.abspath(os.path.dirname(__file__)), os.pardir)))

from httpclient import HttpClient
import unittest


class Test_serv(unittest.TestCase):

    def setUp(self):
        self.file_path = os.path.abspath(os.path.dirname(__file__))

        my_headers = [('User-Agent', 'Mozilla/4.0'), ('X-From', 'UA')]
        my_user_pass = ('kiril', 'supersecret')

        self.client = HttpClient(
            # load cookie from file before query
            load_cookie=os.path.join(self.file_path, 'cookie.txt'),
            # save cookie to file after query
            save_cookie=os.path.join(self.file_path, 'cookie.txt'),
            connect_timeout=10,         # socket timeout on connect
            transfer_timeout=30,        # socket timeout on send/recv
            max_redirects=10,           # follow Location: header on 3xx response
            set_referer=True,           # set Referer: header when follow location
            keep_alive=3,               # Keep-alive socket up to N requests
            headers=my_headers,         # send custom headers
            http_version="1.1",         # use custom http/version
            auth=my_user_pass,          # http auth
            retry=5,                    # try again on socket or http/5xx errors
            retry_delay=10)             # wait betweet tries

    def tearDown(self):
        pass

    def test_page(self):        
        res = self.client.post('http://127.0.0.1:8080/update',
                          data={'key': 'value', 'mama': 'papa'})
        
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")
        # перевірка на наявність тега кук key=value
        self.assertRegex(res.headers['Set-Cookie'][0], "key=value")
        # перевірка message body
        self.assertRegex(res.body, "<h1>Hello world</h1>")

    

        res = self.client.get('http://127.0.0.1:8080/kira')        
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")
        # перевірка на наявності контент тайпа
        self.assertRegex(res.headers['Content-Type'], "text/html")
        # перевірка message body
        self.assertRegex(res.body, "<h1>Hello /kira</h1>")



    
        res = self.client.get('http://127.0.0.1:8080/cookie',
                                            params={"key":"mama"})

        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")
        # перевірка на наявності контент тайпа
        self.assertRegex(res.headers['Content-Type'], "text/html")
        # перевірка message body
        self.assertRegex(res.body, "mama = papa")

    

        res = self.client.get('http://127.0.0.1:8080/')
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")



    def test_wrong_page(self):
        res = self.client.get('http://127.0.0.1:8080/wrong_page.,!@#$%^&*(WTF_page)')
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "404")





if __name__ == '__main__':
    unittest.main()

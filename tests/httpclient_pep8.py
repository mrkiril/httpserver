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


class SocketFallError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class HttpClient(object):
    """ Main class of this library.
        It contain GET, POST, PUT, DELETE, HEAD methods.

        Attributes:
            load_cookie: load cookie from file before query
            save_cookie: save cookie to file after query
            connect_timeout: socket timeout on connect
            transfer_timeout: socket timeout on send/recv
            max_redirects: follow Location: header on 3xx response
            set_referer: set Referer: header when follow location
            keep_alive: Keep-alive socket up to N requests

            And logger of library can call'd like self.logger 
    """

    def __init__(self, **kwargs):
        # create logger
        self.logger = logging.getLogger('htttp_lib')
        # self.logger.setLevel(logging.INFO)
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        self.load_cookie = os.path.join(self.file_path,'cookie.txt')
        self.save_cookie = os.path.join(self.file_path,'cookie.txt')
        self.connect_timeout = 10
        self.transfer_timeout = 30
        self.max_redirects = 10
        self.set_referer = True
        self.keep_alive = 3
        # send custom headers
        self.headers_for_request = [
            ('User-Agent', 'Opera/9.80 (iPhone; Opera Mini/7.0.4/28.2555;'
             'U; fr) Presto/2.8.119 Version/11.10'), ('X-From', 'UA')]
        self.http_version = "1.1"
        self.auth = None
        self.retry = 5
        self.retry_delay = 10

        if "load_cookie" in kwargs:
            self.load_cookie = kwargs["load_cookie"]
        if "save_cookie" in kwargs:
            self.save_cookie = kwargs["save_cookie"]
        if "connect_timeout" in kwargs:
            self.connect_timeout = kwargs["connect_timeout"]
        if "transfer_timeout" in kwargs:
            self.transfer_timeout = kwargs["transfer_timeout"]
        if "max_redirects" in kwargs:
            self.max_redirects = kwargs["max_redirects"]
        if "set_referer" in kwargs:
            self.set_referer = kwargs["set_referer"]
        if "keep_alive" in kwargs:
            self.keep_alive = kwargs["keep_alive"]
        if "headers" in kwargs:
            self.headers_for_request = kwargs["headers"]
        if "http_version" in kwargs:
            self.http_version = kwargs["http_version"]
        if "auth" in kwargs:
            self.auth = kwargs["auth"]
        if "retry" in kwargs:
            self.retry = kwargs["retry"]
        if "retry_delay" in kwargs:
            self.retry_delay = kwargs["retry_delay"]

        
        self.req_line = b""
        self.is_f_req = True
        self.cook_dick = {}
        self.response_str = ""
        # self.soket_dic[Host] = { "socket": sock, "index" : index}
        self.soket_dic = {}
        self.page_status_list = []
        # start methods parametsr
        self.output = None
        self.host = None
        self.cookies = ""
        self.sock = None
        self.max_size = None
        self.proxy = None
        self.proxy_auth = None
        self.retry_index = 0
        # if True in history will be add message body
        self.history_body = None
        # end methods parametrs
        self.status_code = ""
        self.headers = {}
        self.encoding = ""
        self.body = ""
        self.history = []

    
    def __del__(self):
        # self.soket_dic[Host] = { "socket": sock, "index" : index}
        for k, v in self.soket_dic.items():
            v["socket"].close()
        

    def size_base64(self, size_):
        z = (size_ // 3)
        if size_ % 3 != 0:
            z += 1
        return z * 4

    def boundary(self):
        a = string.ascii_lowercase + string.digits
        return ''.join([random.choice(a) for i in range(8)])

    def del_sock(self):
        # delete and close this socket
        try:
            lasthost = self.sock.getpeername()
            key = None
            for k, v in self.soket_dic.items():
                if v["socket"].getpeername() == lasthost:
                    key = k
                    break
            if key is not None:
                self.soket_dic.pop(key)
                self.sock.close()
        except Exception as e:
            pass
        finally:
            if self.host in self.soket_dic:
                self.soket_dic.pop(self.host)

    def connect(self, url, kwargs, headers_all, url_previos, type_req,
                bytes_to_send, transfer_timeout):
        iterator = True
        while iterator:
            try:
                if self.host in self.soket_dic and self.proxy is None:
                    # logger
                    self.logger.info('socket exist')
                    request_str = self.soket_funk(url, kwargs, headers_all,
                                                  url_previos, type_req,
                                                  bytes_to_send)
                    self.sock = self.soket_dic[self.host]["socket"]
                    self.soket_dic[self.host]["index"] += 1
                    result = self.soket_recv(16, transfer_timeout)
                    self.is_f_req = False

                if self.host not in self.soket_dic and self.proxy is None:
                    # logger
                    self.logger.info('socket does not exist')
                    self.sock = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    
                    addr = (self.host, 80)
                    if ":" in self.host:
                        n_host = self.host.split(":")
                        addr =(n_host[0], int(n_host[1]))

                    self.sock.settimeout(self.connect_timeout)
                    self.sock.connect(addr)
                    self.sock.settimeout(None)
                    request_str = self.soket_funk(url, kwargs, headers_all,
                                                  url_previos, type_req,
                                                  bytes_to_send)

                    self.soket_dic[self.host] = {
                        "socket": self.sock, "index": 0}
                    result = self.soket_recv(16, transfer_timeout)
                    self.is_f_req = False

                if self.proxy is not None:
                    is_proxy_exist = False
                    soket_key = None
                    for key, elem in self.soket_dic.items():
                        if self.proxy[0] == str(elem["socket"].getpeername()[0]):
                            is_proxy_exist = True
                            self.sock = elem["socket"]
                            soket_key = key
                            break
                    if not is_proxy_exist:
                        # logger
                        self.logger.info('Proxy socket does not exist')
                        self.sock = socket.socket(socket.AF_INET,
                                                  socket.SOCK_STREAM)
                        addr = (self.proxy[0], self.proxy[1])
                        self.sock.settimeout(self.connect_timeout)
                        self.sock.connect(addr)
                        self.sock.settimeout(None)
                        request_str = self.soket_funk(url, kwargs, headers_all,
                                                      url_previos, type_req,
                                                      bytes_to_send)

                        self.soket_dic[self.proxy[0]] = (
                            {"socket": self.sock, "index": 0})
                        result = self.soket_recv(16, transfer_timeout)
                        self.is_f_req = False
                        self.logger.info('Proxy socket is create')

                    if is_proxy_exist:
                        # logger
                        self.logger.info('Proxy socket exist')
                        request_str = self.soket_funk(url, kwargs, headers_all,
                                                      url_previos, type_req,
                                                      bytes_to_send)

                        self.sock = self.soket_dic[soket_key]["socket"]
                        self.soket_dic[soket_key]["index"] += 1
                        result = self.soket_recv(16, transfer_timeout)
                        self.is_f_req = False

            except ConnectionError as e:
                # logger
                self.logger.error('ConnectionError' + str(e.args))
                self.del_sock()
                return(False, "", "")
            except FileNotFoundError as e:
                # logger
                self.logger.error('FileNotFoundError' + str(e.args))
                self.del_sock()
                return (False, "", "")

            except SocketFallError as e:
                # logger
                self.logger.error('SocketFallError, reload socket ...')
                print(self.soket_dic.keys())
                self.del_sock()
                print(self.soket_dic.keys())
                continue

            except socket.timeout as e:
                self.sock.close()
                self.soket_dic.pop(self.host)
                # logger
                self.logger.error('TimeoutError' + str(e.args))
                return (False, "")

            except OSError as e:
                self.sock.close()
                self.soket_dic.pop(self.host)
                # logger
                self.logger.error('OSError' + str(e.args))
                print(self.soket_dic.keys())
                self.del_sock()
                print(self.soket_dic.keys())
                continue

            else:
                return (True, result, request_str)

    def status_200_300(self,  host_url_and_query, cookie_arr):
        # Find cookies for next iteration
        m_location = re.search("(\w+://)?(([^/]+).*)", host_url_and_query)
        new_Host_url_and_query = m_location.group(2)
        new_Host = m_location.group(3)
        cookies = ""
        cook_part = []
        for key in self.cook_dick.keys():
            if key[0] == ".":
                m_key = re.search(key[1:] +
                                  self.cook_dick[key]["params"]["path"],
                                  new_Host_url_and_query)

            if key[0] != ".":
                m_key = re.match(key + self.cook_dick[key]["params"]["path"],
                                 new_Host_url_and_query)

            if m_key is not None:
                tmp_cook = self.cook_dick[key]["cookie"].copy()
                tmp_cook.update(cookie_arr)
                cook_part.append(
                    "; ".join([k + "=" + v for k, v in tmp_cook.items()]))

        cookies = "; ".join(cook_part)
        return (cookies, host_url_and_query, new_Host)

    def cookies_funk(self, cookies_list, start_host):
        for el_cookies_list in cookies_list:
            m_cook = re.split("; ?", el_cookies_list)
            temp_dick = {}
            for el in m_cook:
                parser_el = re.search("(.+?)=(.+)", el)
                if parser_el is not None:
                    el_key = parser_el.group(1)
                    el_value = re.sub(";", "", parser_el.group(2))
                    temp_dick[el_key] = el_value

            params = {}
            # DOMAIN
            if "domain" not in temp_dick and "Domain" not in temp_dick:
                domain = "." + start_host

            if "domain" in temp_dick or "Domain" in temp_dick:
                if "domain" in temp_dick:
                    domain = temp_dick.pop("domain")
                else:
                    domain = temp_dick.pop("Domain")
            # PATH
            if "path" not in temp_dick and "Path" not in temp_dick:
                params["path"] = "/"

            if "path" in temp_dick or "Path" in temp_dick:
                if "path" in temp_dick:
                    params["path"] = temp_dick.pop("path")

                else:
                    params["path"] = temp_dick.pop("Path")
            # EXPIRES
            if "expires" not in temp_dick and "Expires" not in temp_dick:
                params["expires"] = None
            if "expires" in temp_dick or "Expires" in temp_dick:
                if "expires" in temp_dick:
                    params["expires"] = temp_dick.pop("expires")
                else:
                    params["expires"] = temp_dick.pop("Expires")
            # DICK
            if domain not in self.cook_dick:
                self.cook_dick[domain] = (
                    {"cookie": temp_dick, "params": params})

            if domain in self.cook_dick:
                for key, value in temp_dick.items():
                    self.cook_dick[domain]["cookie"][key] = value

    def soket_funk(self, url, kwargs, headers_all, url_previos,
                   type_of_request, bytes_to_send):
        bound = self.boundary().encode()
        # Create request string
        CRLF = b"\r\n"
        q = (type_of_request.encode() + b" " + url.encode() +
             b" HTTP/" + self.http_version.encode() + CRLF)

        q += b"Host: " + self.host.encode() + CRLF
        if self.cookies:
            q += b"Cookie: " + self.cookies.encode() + CRLF

        if self.set_referer:
            if "referrer" in kwargs:
                q += b"Referrer: " + kwargs["referrer"].encode() + CRLF

            if url_previos != "":
                q += b"Referrer: " + url_previos.encode() + CRLF

        if "auth" in kwargs:
            if self.auth is not None:
                q += b"Authorization: Basic " + base64.standard_b64encode(
                    self.auth[0].encode() + b": " +
                    self.auth[1].encode()) + CRLF

        q += b"Connection: Keep-Alive" + CRLF
        for k, v in headers_all.items():
            q += k.encode() + b": " + v.encode() + CRLF

        if "proxy" in kwargs and "proxy_auth" in kwargs:
            q += b"Proxy-Authorization: Basic " + base64.standard_b64encode(
                self.proxy_auth[0].encode() + b":" +
                self.proxy_auth[1].encode()) + CRLF

            q += b"Proxy-Connection: Keep-Alive" + CRLF
            if "set_via" in kwargs:
                if kwargs["set_via"]:
                    localhost = self.sock.getsockname()
                    lasthost = self.sock.getpeername()
                    via = ("Via: {0} {1}:{2}, 1.1 {3}:{4}, 1.1 {5}".format(
                        self.http_version, localhost[0], localhost[1],
                        lasthost[0], lasthost[1], self.host) +
                        CRLF.decode())

                    q += via.encode()

        if (type_of_request == "HEAD" or type_of_request == "DELETE" or
                type_of_request == "GET"):

            q += CRLF
            self.soket_req(q)
            return None

        if type_of_request == "POST" or type_of_request == "PUT":
            if "data" in kwargs:
                q += b"Content-Type: application/x-www-form-urlencoded" + CRLF
            if "files" in kwargs:
                q += (b"Content-Type: multipart/form-data; "
                      b"boundary=" + bound + CRLF)

            # calculate byte lenght
            if "data" in kwargs:
                payload_el = "&".join([k + "=" + v for k, v in
                                           kwargs["data"].items()])
                byte_len = str(len(payload_el))
                q += b"Content-Length: " + byte_len.encode() + CRLF

            if "files" in kwargs:
                count_files = len(kwargs["files"])
                sum_of = 14 + count_files * 121
                for key, value in kwargs["files"].items():
                    path = os.path.abspath(value.name)
                    size_base64 = self.size_base64(os.path.getsize(path))
                    sum_of += len(os.path.basename(value.name).encode())
                    sum_of += len(key.encode())
                    sum_of += len(
                        mimetypes.guess_type(value.name,
                                             strict=False)[0].encode()
                    )
                    sum_of += size_base64

                byte_len = str(sum_of)
                # last CRLF before entity-body
                q += b"Content-Length: " + byte_len.encode() + CRLF

            q += CRLF
            self.soket_req(q)
            q = b""
            # constructing message body
            # to sending files
            boundary = b"--" + bound
            mimetypes.init()
            is_one_iter = False
            lap = b'''"'''
            if "files" in kwargs:

                for key, value in kwargs["files"].items():
                    bytes_to_send = b""
                    mime = mimetypes.guess_type(value.name, strict=False)
                    # create request string
                    bytes_to_send += boundary + CRLF
                    bytes_to_send += (b"Content-Disposition: form-data; name=" +
                                      lap + key.encode() + lap + b"; filename=" +
                                      lap + os.path.basename(value.name).encode() +
                                      lap + CRLF)

                    bytes_to_send += b"Content-Type: " + \
                        mime[0].encode() + CRLF
                    bytes_to_send += b"Content-Transfer-Encoding: base64" + CRLF
                    #bytes_to_send += b"Content-Transfer-Encoding: binary" + CRLF
                    bytes_to_send += CRLF
                    self.soket_req(bytes_to_send)

                    # debug
                    iterator = True
                    while iterator:
                        try:
                            #file_ = value.read(65536)
                            file_ = base64.standard_b64encode(
                                value.read(65535))
                            self.soket_req(file_)
                            if file_ == b"":
                                iterator = False

                        except FileNotFoundError as e:
                            # logger
                            self.logger.error(
                                "Send file exception: File not found")
                            bytes_to_send = b""
                            break
                        else:
                            is_one_iter = True
                    self.soket_req(CRLF)

                if is_one_iter:
                    last_boundary = boundary + b"--" + CRLF
                    self.soket_req(last_boundary)
            if "data" in kwargs:
                payload_el = "&".join([k + "=" + v for k, v in
                                       kwargs["data"].items()])
                self.soket_req(payload_el.encode())

    def soket_recv(self, byte, transfer_timeout):
        this_stack_bytes = b''

        self.sock.settimeout(transfer_timeout)
        response = self.sock.recv(byte)
        this_stack_bytes += response
        self.sock.settimeout(None)

        if response == b"" and self.is_f_req == False:
            # logger
            self.logger.warning("Socket return Zero")
            return (False, this_stack_bytes)
        if response == b"" and self.is_f_req == True:
            # logger
            self.logger.warning("Socket is fall down")
            raise SocketFallError("Socket is fall down")
            return (False, this_stack_bytes)

        return (True, this_stack_bytes)

    def soket_req(self, q):
        self.sock.settimeout(self.connect_timeout)
        self.sock.send(q)
        self.sock.settimeout(None)
        self.req_line += q
        str_path = os.path.join(self.file_path,"request_str.txt")
        try:
            with open(str_path, "ab") as fp:
                file = fp.write(q)
        
        except FileNotFoundError as e:
            with open(str_path, "wb") as fp:
                file = fp.write(q)
     
    def parslink(self, link):
        m_data_link = re.search("https?://([^/]+).*", link, re.DOTALL)
        if ":" in m_data_link.group(1):
            start_host = m_data_link.group(1)
            start_cook_pattern = m_data_link.group(1)

        if ":" not in m_data_link.group(1):
            pat = re.search("(www\.)?(.*)" ,m_data_link.group(1), re.DOTALL)
            start_host = pat.group()
            start_cook_pattern = pat.group(2)

        url = link
        return (url, start_host, start_cook_pattern)

    def search_headers(self,  all_headers):
        header = {}
        # get out first rows
        all_headers = all_headers[int(re.search(".+?\r\n",
                                                all_headers).span()[1]):]
        # Parsing headers
        summ = ""
        ind = 0
        cookies_list = []
        for i in range(len(all_headers[:-2])):
            summ += all_headers[i]

            if summ.endswith("\r\n"):
                for_dict = re.search("(.+?): (.+)", summ[:-2])
                if for_dict.group(1) == "Set-Cookie":
                    # array of all cookies in Set-Cookie
                    cookies_list.append(for_dict.group(2))
                else:
                    header[for_dict.group(1)] = for_dict.group(2)

                summ = ""
        header["Set-Cookie"] = cookies_list
        return (header, cookies_list)

    def content_length(self, page_bytes, transfer_timeout, kwargs, max_size):
        page = ""
        if "on_headers" in kwargs:
            on_headers = kwargs["on_headers"](self.headers)
            if not on_headers:
                # logger
                self.logger.warning("on_headers is drop download ...")
                return (False, page)

        if "on_progress" in kwargs:
            on_progress = kwargs["on_progress"]

        if int(self.headers["Content-Length"]) > 0:

            if "output" in kwargs:
                with open(kwargs["output"], "wb") as fp:
                    fp.write(page_bytes)

            is_stop_recursion = False
            while not is_stop_recursion:
                if len(page_bytes) >= int(self.headers["Content-Length"]):
                    if "output" in kwargs:
                        # logger
                        self.logger.info("Download to file is complited.")
                    break

                response = self.soket_recv(65535, transfer_timeout)
                if "output" in kwargs:
                    with open(kwargs["output"], "ab") as fp:
                        fp.write(response[1])

                if not response[0]:
                    return (False, "")

                if response[0]:
                    page_bytes += response[1]

                if max_size is not None and max_size < len(page_bytes):
                    if self.encoding is None:
                        return(True, page_bytes[0:max_size])
                    else:
                        return(True,
                               page_bytes[0:max_size].decode(self.encoding))

                if "on_progress" in kwargs:
                    on_progress(len(page_bytes),
                                int(self.headers["Content-Length"]))

        if self.encoding is not None:
            page += page_bytes.decode(self.encoding)

        if self.encoding is None:
            page = ""

        return (True, page)

    def transfer_encodong(self, page_bytes, transfer_timeout,
                          kwargs, max_size):

        byte_len = 100
        start_page_index = 0
        page_str = b""
        pattern = re.search(b"(\w+?)\r\n", page_bytes).group(1)
        content_pattern = None

        if "output" in kwargs:
            with open(kwargs["output"], "wb") as fp:
                fp.write(page_bytes)

        if pattern.decode() == "0":
            byte_len = 0
        while byte_len != 0:
            if len(page_bytes[start_page_index:]) < 7:
                response = self.soket_recv(2048, transfer_timeout)
                if response[0]:
                    page_bytes += response[1]
                if not response[0]:
                    return (False, "")

            m_len = re.search(b"(\r\n)?(.+?)\r\n",
                              page_bytes[start_page_index:])

            if m_len is None:
                print("len: ", m_len)
                print(page_bytes[start_page_index:])
                print("\n\n")
                response = self.soket_recv(2048, transfer_timeout)
                if response[0]:
                    page_bytes += response[1]
                if not response[0]:
                    return (False, "")
                continue

            len_len = len(m_len.group())        # len() of LEN  +\r\n
            byte_len = int(m_len.group(2), 16)

            while len(page_bytes[start_page_index + len_len:]) < byte_len:
                response = self.soket_recv(byte_len, transfer_timeout)
                if response[0]:
                    page_bytes += response[1]
                if not response[0]:
                    return (False, "")

            from_ = start_page_index + len_len
            to_ = start_page_index + len_len + byte_len
            this_page = page_bytes[from_: to_]
            page_str += this_page
            # Navigates to the next iteration
            start_page_index += len_len + byte_len
            if "output" in kwargs:
                if max_size is None:
                    with open(kwargs["output"], "ab") as fp:
                        fp.write(this_page)

                if max_size is not None:
                    path = kwargs["output"]
                    file_size = os.path.getsize(path)
                    with open(kwargs["output"], "ab") as fp:
                        if file_size + len(this_page) < max_size:
                            fp.write(this_page)

                        else:
                            part_this_page = max_size - file_size
                            fp.write(this_page[0:part_this_page])
                            break

        if max_size is None:
            if self.encoding is not None:
                page = page_str.decode(self.encoding)
            if self.encoding is None:
                page = ''

        if max_size is not None:
            if self.encoding is not None:
                new_page_str = page_str[0: max_size]
                page = new_page_str.decode(self.encoding)

            if self.encoding is None:
                page = ''

        return (True, page)

    def connection_close(self, page_bytes,
                         transfer_timeout, kwargs, max_size):

        is_stop_recursion = True
        if "Content-Type" in self.headers:
            content_pattern = re.search("text", self.headers["Content-Type"])

        if "output" in kwargs:
            start_page_index = len(page_bytes)
            with open(kwargs["output"], "wb") as fp:
                fp.write(page_bytes)

        while is_stop_recursion:
            response = self.soket_recv(65535, transfer_timeout)
            page_bytes += response[1]
            if "output" in kwargs:
                with open(kwargs["output"], "ab") as fp:
                    fp.write(page_bytes[start_page_index:])
                start_page_index = len(page_bytes)

            if max_size is not None:
                if len(page_bytes) <= max_size:
                    return (True, page_bytes[:max_size].decode(self.encoding))

            endof = re.search(b"</html>", response[1])
            if endof is not None:
                return (True, page_bytes.decode(self.encoding))

            if not response[0]:
                if self.encoding is None:
                   return (True, page_bytes.decode("utf-8")) 
                return (True, page_bytes.decode(self.encoding))

    def load_cookies(self, directory):
        try:
            with open(directory, "r", encoding='utf-8') as fp:
                file = fp.read()
        except FileNotFoundError as e:
            # logger
            self.logger.warning("Coockie's file not found")
            return {}
        else:
            return json.loads(file)

    def write_cookies(self, cook_dick, directory):
        cookies_json = json.dumps(cook_dick, separators=(',', ':'))        
        with open(directory, "w", encoding='utf-8') as fp:
            fp.write(cookies_json)

    def cookies_constr(self, cook_arr, link, start_cook_pattern ):        
        for small_dick in self.cook_dick.keys():
            in_cook_dick = re.search(start_cook_pattern + "$", small_dick)
            if in_cook_dick is not None:
                cookies_url = self.status_200_300(link, cook_arr)
                return cookies_url[0]
                break
                
        return None    

    def structure(self, url, kwargs, headers_all, url_previos, type_req,
                  bytes_to_send, transfer_timeout, redirect_counter,
                  max_redir, max_size, retry):

        # Start structure
        is_stop_recursion = False
        while not is_stop_recursion:
            self.status_code = ""
            self.headers = {}
            self.encoding = ""
            self.body = ""

            # def connect( request_str ):
            response = self.connect(url, kwargs, headers_all, url_previos,
                                    type_req, bytes_to_send, transfer_timeout)
            if response[0]:
                # logger
                self.logger.info("Connection to socket is OK")
                result = response[1]
                request_str = response[2]

            if not response[0]:
                # logger
                self.logger.critical("Connection to socket: ERROR")
                break

            first_str = result[1].decode("ascii")
            page = ""  # Variable which will be returnes(NOT BYTES)
            start_index = None  # Startindex of message body
            status = re.search("HTTP.*? (\d+) ", first_str)
            if status is None:
                # logger
                self.logger.error("Critical ERROR: No status code!")
                break
            self.status_code = status.group(1)

            if status is not None:
                if status.group(1)[0] == "5":
                    if (self.retry_index >= retry and
                            self.raise_on_error):

                        # logger
                        self.logger.error(
                            "You have 5-th ERROR of 5xx http response")
                        continue
                    time.sleep(self.retry_delay)
                    self.retry_index += 1

                if status.group(1)[0] == "4":
                    # logger
                    self.logger.error(
                        "You have 4-th ERROR of 4xx http response")
                    self.logger.info("Enter correct informations")
                    self.encoding = ""
                    self.body = ""
                    self.history = []
                    self.headers = {}
                    return self
                    break

                if status.group(1)[0] == "3" or status.group(1)[0] == "2":
                    if type_req == "DELETE" and status.group(1)[0] == "3":
                        # logger
                        self.logger.error(
                            "You have 3-th ERROR of 3xx http response")
                        self.logger.info(
                            "for DELETE method Enter correct informations")
                        break

                    this_stack_bytes = result[1]
                    iterator = True
                    while iterator:
                        response = self.soket_recv(4096, transfer_timeout)
                        if response[0]:
                            this_stack_bytes += response[1]

                        if not response[0]:
                            # logger
                            self.logger.error("ERROR: First 4096 byte error")
                            break

                        m_headers = re.search(b".+?\r\n\r\n",
                                              this_stack_bytes, re.DOTALL)

                        if m_headers is not None:
                            break

                    all_headers = m_headers.group().decode("ascii")
                    headers_and_startindex = self.search_headers(all_headers)
                    # start index of message body
                    start_index = m_headers.span()[1]
                    cookies_list = headers_and_startindex[1]
                    self.headers = headers_and_startindex[0]

                    self.encoding = None
                    if "Content-Type" in self.headers:

                        charset_list = ["text", "json"]
                        charset = re.search("charset=(.*);?",
                                            self.headers["Content-Type"])

                        if charset is not None:
                            self.encoding = charset.group(1)
                        elif self.headers["Content-Type"].find("text") != -1:
                            self.encoding = "utf-8"
                        elif self.headers["Content-Type"].find("json") != -1:
                            self.encoding = "utf-8"

                    # cookies_list string with cookies (not parsinf).
                    self.cookies_funk(cookies_list, self.host)
                    if not type_req == "HEAD":
                        self.response_str = this_stack_bytes[:start_index]
                        # Content-Length
                        if "Content-Length" in self.headers:
                            # logger
                            self.logger.info(
                                "Type of download: Content-Length")

                            response = self.content_length(
                                page_bytes=this_stack_bytes[start_index:],
                                transfer_timeout=transfer_timeout,
                                kwargs=kwargs,
                                max_size=max_size)

                            if response[0]:
                                # logger
                                self.logger.info("Content Len: OK")
                                page += response[1]

                            if not response[0]:
                                # logger
                                self.logger.error("Content Len: ERROR")
                                break

                            self.body = page
                        # Chanked
                        if "Transfer-Encoding" in self.headers:
                            # logger
                            self.logger.info(
                                "Type of download: Transfer-Encoding")
                            response = self.transfer_encodong(
                                page_bytes=this_stack_bytes[start_index:],
                                transfer_timeout=transfer_timeout,
                                kwargs=kwargs,
                                max_size=max_size)

                            if response[0]:
                                # logger
                                self.logger.info("Chanked: OK")
                                page += response[1]
                            if not response[0]:
                                # logger
                                self.logger.error("Chanked: ERROR")
                                break
                            self.body = page

                        # Conection Closed
                        if ("Transfer-Encoding" not in self.headers and
                                "Content-Length" not in self.headers):
                            # logger
                            self.logger.info(
                                "Type of download: Connection_close")
                            response = self.connection_close(
                                page_bytes=this_stack_bytes[start_index:],
                                transfer_timeout=transfer_timeout,
                                kwargs=kwargs,
                                max_size=max_size)

                            if response[0]:
                                # logger
                                self.logger.info("Conection close: OK")
                                page += response[1]
                                self.del_sock()

                            if not response[0]:
                                # logger
                                self.logger.error("Conection close: ERROR")
                                break
                            self.body = page

                    # With domain allocates part .example.xxx
                    # and correlate it to link transition.
                    # And extracts the cookie for this domain.
                    # In case nothing matches pond

                    # Status 200
                    if status.group(1) == "200":
                        # logger
                        self.logger.info("Status code: 200")
                        self.logger.info("GO TO >>>>>>>>>>> EXIT")

                    # Status 301 or 302
                    if status.group(1) == "301" or status.group(1) == "302":
                        if "Location" in self.headers:
                            # logger
                            self.logger.info("Status code: " +
                                             str(self.status_code))
                            self.logger.info("REDIRECT TO >>>" +
                                             str(self.headers["Location"]))

                            cookies_url = self.status_200_300(
                                self.headers["Location"], {})
                            url_previos = url       # url for Referrer
                            url = cookies_url[1]    # URL for next step
                            # COOKIE for next step
                            self.cookies = cookies_url[0]
                            self.host = cookies_url[2]  # Host for next step
                            type_req = "GET"

                    self.page_status_list.append(self.status_code)

                    if self.history_body:
                        self.history.append({"headers": self.headers,
                                             "body": self.page})
                    if (not self.history_body or
                            self.history_body is None):
                        self.history.append({"headers": self.headers,
                                             "body": ""})

            # Delete and Close Soсket if we have Connection: close
            if "Connection" in self.headers:
                if self.headers["Connection"].lower() == "close":
                    self.del_sock()

            # self.soket_dic[Host] = { "soket": sock, "index" : index}
            # Delete and Close Soсket if index >

            for k, v in self.soket_dic.items():
                if v["index"] > self.keep_alive:
                    v['socket'].close()

            self.soket_dic = ({key: value for key, value
                               in self.soket_dic.items()
                               if value["index"] <= self.keep_alive})

            # END
            if 1 <= len(self.page_status_list):
                if self.page_status_list[-1] == "200":
                    # write cook to the file
                    self.write_cookies(self.cook_dick, self.save_cookie)
                    return self

                    break

            # Counter of redirext
            redirect_counter += 1

            if redirect_counter >= max_redir:
                return self
                break

    def get(self, link, **kwargs):
        """GET http request.

           Request for take data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.  
                headers: Dickt of reaponse headers 
                body: message body 
                history: list of redirect history

        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        bytes_to_send = None
        is_stop_recursion = False
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.raise_on_error = False

        payload_el = ""
        headers_all = dict(self.headers_for_request)
        if "params" in kwargs:
            payload_dick = {}
            for key, value in kwargs["params"].items():
                value = "+".join(re.split(" ", value))
                payload_dick[key] = value

            payload_el ="?"+"&".join(
                [k + "=" + v for k, v in payload_dick.items()])

        # headers={'User-Agent': 'Opera/9.0'},
        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        # Take from link: Host, Cookies pattern
        link_el = self.parslink(link)
        url = link_el[0] + payload_el
        start_host = link_el[1]
        start_cook_pattern = link_el[2]

        self.host = start_host
        #print("start_cook_pattern:", start_url_and_query)
        #print("start_host:", start_host)
        #print("start_cook_pattern:", start_cook_pattern)
        #_=input("Break point ...")

        
        # Fiemd Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)        
        cook_arr={}
        if "cookie" in kwargs:
            cook_arr=kwargs["cookie"]
        self.cookies = self.cookies_constr(                            
                            cook_arr=cook_arr,
                            link=link,
                            start_cook_pattern=start_cook_pattern)
        
        
        

        return self.structure(
            url=url,
            kwargs=kwargs,
            headers_all=headers_all,
            url_previos=url_previos,
            type_req="GET",
            bytes_to_send=bytes_to_send,
            transfer_timeout=transfer_timeout,
            redirect_counter=redirect_counter,
            max_redir=max_redir,
            max_size=max_size,
            retry=retry)

    def post(self, link, **kwargs):
        """POST http request.

           Request for take data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry 12) data or file

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.  
                headers: Dickt of reaponse headers 
                body: message body 
                history: list of redirect history

        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        is_stop_recursion = False
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.raise_on_error = False
        self.cook_dick = self.load_cookies(self.load_cookie)

        payload_el = ""
        headers_all = dict(self.headers_for_request)
        bytes_to_send = None
        CRLF = b"\r\n"

        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])
       

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        # Take from link: Host, Cookies pattern
        link_el = self.parslink(link)
        url = link_el[0]              # URL for Request
        start_host = link_el[1]
        start_cook_pattern = link_el[2]

        #m_data_link = re.search("https?://(.+?\.(.+?))(/.*)", link, re.DOTALL)
        #start_url_and_query = link
        #start_host = m_data_link.group(1)
        #start_cook_pattern = m_data_link.group(2)

        self.page_status_list = []
        self.host = start_host
        self.cookies = ""
                 
        # Fiemd Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)        
        cook_arr={}
        if "cookie" in kwargs:
            cook_arr=kwargs["cookie"]
        self.cookies = self.cookies_constr(                            
                            cook_arr=cook_arr,
                            link=link,
                            start_cook_pattern=start_cook_pattern)


        return self.structure(
            url=url,
            kwargs=kwargs,
            headers_all=headers_all,
            url_previos=url_previos,
            type_req="POST",
            bytes_to_send=bytes_to_send,
            transfer_timeout=transfer_timeout,
            redirect_counter=redirect_counter,
            max_redir=max_redir,
            max_size=max_size,
            retry=retry)

    def put(self, link, **kwargs):
        """PUT http request.

           Request for take data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry 12) data or file

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.  
                headers: Dickt of reaponse headers 
                body: message body 
                history: list of redirect history

        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        is_stop_recursion = False
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.raise_on_error = False
        self.cook_dick = self.load_cookies(self.load_cookie)

        payload_el = ""
        headers_all = dict(self.headers_for_request)
        bytes_to_send = None
        CRLF = b"\r\n"
        # headers={'User-Agent': 'Opera/9.0'},
        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        # Take from link: Host, Cookies pattern
        m_data_link = re.search("https?://(.+?\.(.+?))(/.*)", link, re.DOTALL)
        start_url_and_query = link
        start_host = m_data_link.group(1)
        start_cook_pattern = m_data_link.group(2)

        self.page_status_list = []
        self.host = start_host
        url = start_url_and_query

        # Fiemd Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)        
        cook_arr={}
        if "cookie" in kwargs:
            cook_arr=kwargs["cookie"]
        self.cookies = self.cookies_constr(                            
                            cook_arr=cook_arr,
                            link=link,
                            start_cook_pattern=start_cook_pattern)
        
        return self.structure(
            url=url,
            kwargs=kwargs,
            headers_all=headers_all,
            url_previos=url_previos,
            type_req="PUT",
            bytes_to_send=bytes_to_send,
            transfer_timeout=transfer_timeout,
            redirect_counter=redirect_counter,
            max_redir=max_redir,
            max_size=max_size,
            retry=retry)

    def delete(self, link, **kwargs):
        """DELETE http request.

           Request for delete data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.  
                headers: Dickt of reaponse headers 
                body: message body 
                history: list of redirect history

        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        is_stop_recursion = False
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.cook_dick = self.load_cookies(self.load_cookie)

        payload_el = ""
        headers_all = dict(self.headers_for_request)
        bytes_to_send = None
        CRLF = b"\r\n"
        # headers={'User-Agent': 'Opera/9.0'},
        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])


        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        # Specific
        self.raise_on_error = False
        if "raise_on_error" in kwargs:
            self.raise_on_error = kwargs["raise_on_error"]

        count_files = 0
        bytes_to_send = b""

        # Take from link: Host, Cookies pattern
        m_data_link = re.search("https?://(.+?\.(.+?))(/.*)", link, re.DOTALL)
        start_url_and_query = link
        start_host = m_data_link.group(1)
        start_cook_pattern = m_data_link.group(2)

        self.page_status_list = []
        self.host = start_host
        url = start_url_and_query

        # Fiemd Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)        
        cook_arr={}
        if "cookie" in kwargs:
            cook_arr=kwargs["cookie"]
        self.cookies = self.cookies_constr(                            
                            cook_arr=cook_arr,
                            link=link,
                            start_cook_pattern=start_cook_pattern)

        return self.structure(
            url=url,
            kwargs=kwargs,
            headers_all=headers_all,
            url_previos=url_previos,
            type_req="DELETE",
            bytes_to_send=bytes_to_send,
            transfer_timeout=transfer_timeout,
            redirect_counter=redirect_counter,
            max_redir=max_redir,
            max_size=max_size,
            retry=retry)

    def head(self, link, **kwargs):
        """HEAD http request.

           Request for delete data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.  
                headers: Dickt of reaponse headers
                history: list of redirect history

        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        bytes_to_send = None
        is_stop_recursion = False
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.raise_on_error = False
        self.cook_dick = self.load_cookies(self.load_cookie)

        payload_el = ""
        headers_all = dict(self.headers_for_request)

        if "params" in kwargs:
            payload_dick = {}
            for key, value in kwargs["params"].items():
                value = "+".join(re.split(" ", value))
                payload_dick[key] = value

            payload_el = "&".join([k + "=" + v for
                                   k, v in payload_dick.items()])

        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        # Take from link: Host, Cookies pattern
        m_data_link = re.search("https?://(.+?\.(.+?))(/.*)", link, re.DOTALL)
        start_url_and_query = link + payload_el
        start_host = m_data_link.group(1)
        start_cook_pattern = m_data_link.group(2)

        self.page_status_list = []
        self.host = start_host        
        
        url = start_url_and_query

        # Fiemd Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)        
        cook_arr={}
        if "cookie" in kwargs:
            cook_arr=kwargs["cookie"]
        self.cookies = self.cookies_constr(                            
                            cook_arr=cook_arr,
                            link=link,
                            start_cook_pattern=start_cook_pattern)

        return self.structure(
            url=url,
            kwargs=kwargs,
            headers_all=headers_all,
            url_previos=url_previos,
            type_req="HEAD",
            bytes_to_send=bytes_to_send,
            transfer_timeout=transfer_timeout,
            redirect_counter=redirect_counter,
            max_redir=max_redir,
            max_size=max_size,
            retry=retry)

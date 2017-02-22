#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import os.path
import re
from email.utils import formatdate
import logging
from multiprocessing import Process
from multiprocessing import Pipe
from time import sleep
import signal
import errno


class HttpErrors(Exception):

    """Class HttpErrors
    Need to construct answer of invalid request and mistakes server.
    Method "getter" construct answer to the request
    """

    def __init__(self, err_number, headers={}):
        self.err_number = err_number
        self.headers = headers

    def __str__(self):
        return repr("HTTP ERROR " + self.err_number +
                    " - " + HtCode.get_story(str(self.err_number)))

    def geterr(self):
        content = "<h1>HTTP ERROR " + \
            str(self.err_number) + " - " + \
            HtCode.get_story(self.err_number) + "</h1>"
        r = HttpResponse(status_code=self.err_number,
                         headers=self.headers)

        r.content_type = 'text/html'
        r.content = content
        if self.err_number == 404:
            with open(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                   "pages",
                                   "404.html")) as fp:
                r.content = fp.read()

        if self.err_number == 418:
            with open(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                   "pages",
                                   "418.html")) as fp:
                r.content = fp.read()

        return r


class HtCode(object):

    """
    Http Code class

    Input the number of http code. And method get_story
    retun an subscribe of it
    """
    http_codes = {
        "200": "OK",
        "301": "Moved Permanently",
        "302": "Moved Temporarily",
        "400": "Bad Request",
        "404": "Not Found",
        "405": "Method Not Allowed ",
        "408": "Request Timeout",
        "414": "Request-URL Too Long",
        "415": "Unsupported Media Type",
        "418": "I'm a teapot ",
        "423": "Locked",
        "500": "Internal Server Error",
        "501": "Not Implemented",
        "502": "Bad Gateway",
        "503": "Service Unavailable",
        "504": "Gateway Timeout",
        "505": "HTTP Version Not Supported"
    }

    @staticmethod
    def get_story(code):
        return HtCode.http_codes[str(code)]


class ZeroAnswer(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class HttpRequest(object):

    """ Class HttpRequest of this project.
        This class only construc structure of
        request
    """

    def __init__(self, COOKIE, scheme, body, path, method, encoding,
                 content_type, FILES, headers,
                 GET=None, POST=None, text=None):

        self.scheme = scheme
        self.body = body
        self.path = path
        self.method = method
        self.encoding = encoding
        self.content_type = content_type
        self.FILES = FILES
        self.headers = headers
        self.COOKIE = COOKIE
        self.GET = GET
        self.POST = POST
        self.text = text


class HttpResponse(object):

    """ Class HttpResponse of this server.
        It contain resp_constr methods.
        Which can make response
        Attributes:
            self.status_code
            self.story_code
            self.content_type
            self.location
            self.content
            self.set_cookies
    """

    def __init__(self, *args, **kwargs):
        self.status_code = 200
        self.story_code = "OK"
        self.content_type = "text/html"
        self.headers = {}
        # redirect location
        self.location = "/"
        self.content = None
        self.set_cookies = {}
        self.text = None

        for ar in args:
            self.content = ar

        if "status_code" in kwargs:
            self.status_code = kwargs["status_code"]

        self.story_code = HtCode.get_story(self.status_code)

        if "content_type" in kwargs:
            self.content_type = kwargs["content_type"]

        if "location" in kwargs:
            self.location = kwargs["location"]

        if "headers" in kwargs:
            self.headers = kwargs["headers"]

    def set_cookie(self, key, value):
        self.set_cookies[key] = value
        return self.set_cookies

    def resp_constr(self):
        dt = formatdate(timeval=None, localtime=False, usegmt=True)
        CRLF = "\r\n"
        q = ""

        if str(self.status_code)[0] in ["2", "3", "4", "5"]:
            q += "HTTP/1.1 {0} {1}".format(self.status_code,
                                           self.story_code) + CRLF
            if self.headers != {}:
                for k, v in self.headers.items():
                    q += str(k) + ": " + str(v) + CRLF
            q += "Connection: close" + CRLF
            if self.content is not None:
                byte_len = str(len(self.content))
                q += "Content-Length: " + str(byte_len) + CRLF
                q += "Content-Type: " + \
                    str(self.content_type) + "; charset=utf-8" + CRLF
            if self.set_cookie != {}:
                for k, v in self.set_cookies.items():
                    q += ("Set-Cookie: {0}={1}; expires=Fri,"
                          " 31 Dec 2019 23:59:59 GMT; path=/\r\n".format(
                              k, v, dt))
            if self.status_code in ["301", "302"]:
                q += "Location: " + self.location + CRLF

            q += "Date: " + dt + CRLF
            q += CRLF
        if self.content is not None:
            q += self.content

        return q


class BaseServer(object):

    """ Main class of this server.
        It contain serve_forever methods.
        Which can take request to the socket and give
        an opportunity to send some response to it

    """
    file_path = os.path.abspath(os.path.dirname(__file__))

    def __init__(self, ip, port):
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        self.ip = ip
        self.port = port
        self.reqlink = ""
        self.serv_sock = None
        self.client_sock = None
        self.client_addr = None
        self.table = []
        self.logger = logging.getLogger(__name__)
        self.ISTERM = False
        self.configure()

    def __exit__(self):
        self.serv_sock.close()
        for proc in self.allProcesses.keys():
            self.logger.info(str(proc))
            os.kill(proc, signal.SIGKILL)

    def setting(self):
        pass

    def configure(self):
        pass

    def add_route(self, link, function, method=["GET"]):
        self.table.append({"link": link, "funk": function, "method": method})

    def find_headers(self,  all_headers):
        headers = {}
        hblock = all_headers.split("\r\n")
        for bl in hblock:
            bl_patt = bl.split(": ")
            headers[bl_patt[0].lower()] = bl_patt[1]
        return headers

    def recv_data(self, byte):
        self.client_sock.settimeout(10)
        request = self.client_sock.recv(byte)
        self.client_sock.settimeout(None)
        return request

    def send_data(self, byte):
        self.client_sock.settimeout(10)
        num = self.client_sock.send(byte)
        self.logger.info("server send: " + str(num))
        self.client_sock.settimeout(None)

    def get_method(self, link):
        args = {}
        if "?" not in link:
            pass
        if "?" in link:
            arr = "".join(link.split("?")[1:])
            for ar in arr.split("&"):
                pat = ar.split("=")
                args[pat[0]] = pat[1]
        return args

    def post_method(self, this_t, headers):
        this_t = this_t.decode()
        p_par = {}
        p_body = ""
        p_files = []
        if "content-type" in headers:
            if headers["content-type"] == "application/x-www-form-urlencoded":
                for ar in this_t.split("&"):
                    if "=" in ar:
                        pat = ar.split("=", 1)
                        if pat[0] in p_par:
                            p_par[pat[0]].append(pat[1])
                        else:
                            p_par[pat[0]] = [pat[1]]

                    elif "=" not in ar and len(ar) != 0:
                        if ar in p_par:
                            p_par[ar].append("")
                        else:
                            p_par[ar] = [""]

                for k, v in p_par.items():
                    if len(v) == 1:
                        p_par[k] = v[0]

            pat = re.search("multipart/", headers["content-type"])
            if pat is not None:
                raise HttpErrors(405)
        return (p_par, p_body, p_files)

    def content_length2(self, text, c_len, end):
        if len(text[end:]) < c_len:
            text += self.recv_data(c_len)
        return text

    def req_line(self):
        req = b""
        for i in range(10):
            req += self.recv_data(20)
            fline_pat = re.match(br"^\s*?(\w+) ([^ ]+) ([^ ]+)\r\n", req)
            if fline_pat is not None:
                break
        if fline_pat is None:
            raise HttpErrors(414)
        inp_met = fline_pat.group(1).decode()
        path = fline_pat.group(2).decode()
        scheme = fline_pat.group(3).decode()
        req_req = req[fline_pat.span()[1]:]
        return (inp_met, path, scheme, req_req)

    def take_req(self):
        CRLF = b"\r\n"
        get_params = None
        post_params = None
        post_body = None
        post_fies = None
        COOKIE = {}
        meth = ["GET", "POST", "HEAD", "DELETE", "PUT"]
        inp_met, path, scheme, text = self.req_line()
        if inp_met in meth:
            while True:
                text += self.recv_data(65536)
                if b"\r\n\r\n" in text:
                    start, end = re.search(b"\r\n\r\n", text).span()
                    headers = self.find_headers(text[:start].decode())
                    if inp_met == "GET":
                        get_params = self.get_method(path)
                        content_type = None
                        if "content-type" in headers:
                            content_type = headers["content-type"]

                        accept_encoding = None
                        if "accept-encoding" in headers:
                            accept_encoding = headers["accept-encoding"]
                        break

                    if inp_met == "POST" or inp_met == "PUT":
                        content_type = None
                        if "content-type" in headers:
                            content_type = headers["content-type"]

                        accept_encoding = None
                        if "accept-encoding" in headers:
                            accept_encoding = headers["accept-encoding"]

                        if "content-length" in headers:
                            text = self.content_length2(
                                text,
                                int(headers["content-length"]),
                                end)

                        post_params, post_body, post_fies = self.post_method(
                            text[end:], headers)
                        break

            if "cookie" in headers:
                if "; " in headers["cookie"]:
                    for coo in headers["cookie"].split("; "):
                        cook_arr = coo.split("=")
                        COOKIE[cook_arr[0]] = cook_arr[1]

                if "; " not in headers["cookie"]:
                    cook_arr = headers["cookie"].split("=")
                    COOKIE[cook_arr[0]] = cook_arr[1]

            http_req = HttpRequest(
                text=text,
                GET=get_params,
                POST=post_params,
                COOKIE=COOKIE,
                scheme=scheme,
                body=post_body,
                path=path,
                method=inp_met,
                encoding=accept_encoding,
                content_type=content_type,
                FILES=post_fies,
                headers=headers)
        else:
            raise HttpErrors(400)

        return http_req

    def pathfinder(self, link):
        s_path = link
        if "?" in link:
            s_path = link.split("?")[0]

        re_path = re.match("(https?://)?[^/]*(.*)", s_path, re.DOTALL)
        return re_path.group(2)

    def proc_terminate(self):
        keys = list(self.allProcesses.keys())[:]
        for pid in keys:
            if pid == self.master_pid:
                continue
            # close process
            self.logger.info("Just and kill >> " + str(pid))
            if self.allProcesses[pid].is_alive():
                # close pid_dick_status means Pipe()
                self.pid_dick_status[pid][1].close()
                self.allProcesses[pid].terminate()
            # clear all process and Pipes
            self.pid_dick_status.pop(pid)
            self.allProcesses.pop(pid)

    def create_process(self):
        parent_conn, child_conn = Pipe()
        p = Process(
            target=self.serve_multi,
            daemon=True,
            name='more_',
            args=(child_conn,))
        p.start()
        self.allProcesses[p.pid] = p
        self.pid_dick_status[p.pid] = ["off", parent_conn]

    def master_process(self):
        try:
            sleep(0.01)
            if self.ISTERM:
                command = "y"
                raise KeyboardInterrupt('outside INTERUPT signal')

            for k, v in self.pid_dick_status.items():
                if v[1].poll():
                    try:
                        v[0] = v[1].recv()
                    except EOFError:
                        continue

            arr = [v[0] for k, v in self.pid_dick_status.items()]
            if arr.count("off") < 2:
                self.create_process()

        except KeyboardInterrupt as e:
            try:
                print("Are you sure that close the server ? y/n\r\n")
                command = "y"
            except EOFError as e:
                self.logger.info("forced output")
                command = "y"
            if command in ["Y", "y", "Yes", "yes"]:
                self.proc_terminate()
                self.serv_sock.close()
                return "exit"

            else:
                self.proc_terminate()
                self.ISTERM = False

    def serve_multi(self, child_conn):
        self.child_conn = child_conn
        while True:
            child_conn.send("off")
            self.logger.info('Wait for conection ... ' + str(os.getpid()))
            try:
                self.client_sock, self.client_addr = self.serv_sock.accept()
                child_conn.send("on")
                http_req = self.take_req()
                s_path = self.pathfinder(http_req.path)
                for it in range(len(self.table)):
                    link_pat = re.search(self.table[it]["link"], s_path)
                    if link_pat is None and it == (len(self.table) - 1):
                        raise HttpErrors(404)

                    if link_pat is not None:
                        self.logger.info(
                            self.table[it]["link"] + "\t" + http_req.path)

                        if http_req.method not in self.table[it]["method"]:
                            raise HttpErrors(
                                415, {"Allow": ", ".join(
                                    self.table[it]["method"])})

                        else:
                            http_resp = self.table[it][
                                "funk"](request=http_req)

                        response = http_resp.resp_constr()
                        self.send_data(response.encode())
                        self.client_sock.close()
                        self.logger.info("End")
                        break

            except KeyboardInterrupt as e:
                break

            except socket.timeout as e:
                self.logger.info("Time Out of Socket")
                err = "<h1>Time Out of Socket</h1>"
                self.client_sock.send(err.encode())
                self.client_sock.close()

            except socket.error as e:
                self.logger.info("Error Socket. " + str(os.strerror(e.errno)))
                self.client_sock.close()

            except HttpErrors as e:
                err = e.geterr().resp_constr()
                self.logger.info("Http error: " + str(e.err_number))
                self.client_sock.send(err.encode())
                self.client_sock.close()

    def serve_forever(self):
        self.logger = logging.getLogger(__name__)
        self.serv_sock = socket.socket()
        self.serv_sock.bind((self.ip, self.port))
        self.serv_sock.listen(1000)
        self.pid_dick_status = {}
        self.allProcesses = {}
        self.allProcesses[os.getpid()] = "master"
        self.master_pid = os.getpid()
        signal.signal(signal.SIGINT, self.signal_inter_master_handler)
        for i in range(2):
            self.create_process()

        while True:
            is_exit = self.master_process()
            if is_exit == "exit":
                self.logger.info("Server is off. Bye!)")
                break
            else:
                continue

    def signal_inter_master_handler(self, signal, frame):
        self.ISTERM = True

    def signal_term_child_handler(self, signal, frame):
        self.child_conn.close()

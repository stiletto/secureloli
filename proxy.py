#!/usr/bin/env python
#
# GET/POST/HEAD proxy with websocket support.
#
# Based on simple asynchronous HTTP proxy with tunnelling (CONNECT).
# https://github.com/senko/tornado-proxy/tree/master/tornado_proxy
#
# GET/POST proxying based on
# http://groups.google.com/group/python-tornado/msg/7bea08e7a049cf26
#
# Copyright (C) 2012 Stiletto <blasux@blasux.ru>
# Copyright (C) 2012 Senko Rasic <senko.rasic@dobarkod.hr>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import sys
import socket

import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
import tornado.httpclient
import httplib
import datetime
import time
import traceback
import logging

from tornado.escape import utf8, _unicode, native_str
from tornado.util import b
from tornado.options import define, options, parse_command_line

__all__ = ['ProxyHandler', 'run_proxy']

class Stat(object):
    proxy = 0
    passthrough = 0
    stat = 0
    req = 0
    start = datetime.datetime.utcnow()

define("backend_host", type=str, default="bnw.im", help="Host header which will be sent to backend")
define("backend_connect_host", type=str, default="127.0.0.1", help="Backend address (currently only one)")
define("backend_port", type=int, default=80, help="Backend port")
define("port", type=int, default=8443, help="Port to listen on")
define("address", default="", help="Address to listen on")
define("debug", type=bool, default=False, help="Enable debug messages")

class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'HEAD'] #, 'CONNECT']

    @tornado.web.asynchronous
    def get(self):
        Stat.req += 1
        if self.request.path == '/secureloli/stat':
            Stat.stat += 1
            self.write('Active connections: %d <br/>\n' % (
                Stat.proxy + Stat.passthrough + Stat.stat))
            self.write('Proxy connections: %d <br/>\n' % Stat.proxy)
            self.write('Passthrough connections: %d <br/>\n' % Stat.passthrough)
            self.write('Statistics conenctions: %d <br/>\n' % Stat.stat)
            self.write('Requests served: %d <br/>\n' % Stat.req)
            uptime = datetime.datetime.utcnow() - Stat.start
            days = uptime.days
            hours = uptime.seconds / 3600
            minutes = uptime.seconds / 60 % 60
            seconds = uptime.seconds % 60
            self.write('Uptime: %d days, %d:%02d:%02d <br/>\n' % (days,hours,minutes,seconds))
            self.finish()
            Stat.stat -= 1
            return
        self.request.headers['X-Scheme'] = "https"
        self.request.headers['X-Forwarded-For'] = self.request.remote_ip
        self.request.headers['Host'] = options.backend_host

        connection = map(lambda s: s.strip().lower(), self.request.headers.get("Connection", "").split(","))
        #print connection,self.request.headers['Connection']
        if 'upgrade' in connection:
            logging.info('PASS %s %s %s',self.request.remote_ip,self.request.path,self.request.headers['Connection'])
            try:
                return self.connect()
            except Exception:
                logging.error(traceback.format_exc())
                self.finish()

        Stat.proxy += 1
        stime = time.time()
        logging.info('PROXY %s %s %s',id(self),self.request.remote_ip,self.request.path)

        def handle_response(response):
            self.set_header('Server','secureloli')
            if response.error and not isinstance(response.error,
                    tornado.httpclient.HTTPError):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
                self.finish()
            else:
                if response.code==599:
                    response.code=502
                self.set_status(response.code)
                for header in ('Date', 'Cache-Control', 'Etag',
                        'Content-Type', 'Location', 'Set-Cookie'):
                    v = response.headers.get(header)
                    if v:
                        self.set_header(header, v)
                if response.body:
                    self.write(response.body)
                self.finish()
            rtime = (time.time()-stime)
            if rtime > 1.0:
                logging.error(' vvv ALERT vvv')
            logging.info('DONE %s %s %s %s %s',id(self),response.code,rtime,self.request.remote_ip,self.request.path)
            Stat.proxy -= 1

        assert self.request.path.startswith('/')
        uri = "http://%s:%d%s?%s" % (options.backend_connect_host,options.backend_port,self.request.path,self.request.query)
        req = tornado.httpclient.HTTPRequest(url=uri,
            method=self.request.method, body=self.request.body,
            headers=self.request.headers, follow_redirects=False,
            allow_nonstandard_methods=True)

        client = tornado.httpclient.AsyncHTTPClient()

        try:
            client.fetch(req, handle_response)
        except tornado.httpclient.HTTPError, e:
            if hasattr(e, 'response') and e.response:
                self.handle_response(e.response)
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()
                Stat.proxy -= 1

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def head(self):
        return self.get()

    def connect(self):
        self.active = True
        host, port = (options.backend_connect_host,options.backend_port)
        client = self.request.connection.stream
        Stat.passthrough += 1

        def read_from_client(data):
            if options.debug:
                logging.debug('CLIENT >> %s', data)
            upstream.write(data)

        def read_from_upstream(data):
            if options.debug:
                logging.debug('UPSTREAM >> %s', data)
            client.write(data)

        def client_close(_dummy):
            if options.debug:
                logging.debug('CLIENTCLOSED %s %s',self.request.remote_ip,self.request.path)
            if self.active:
                Stat.passthrough -= 1
                self.active = False
                self.finish()
            upstream.close()

        def upstream_close(_dummy):
            if options.debug:
                logging.debug('UPSTREAMCLOSED %s %s',self.request.remote_ip,self.request.path)
            if self.active:
                Stat.passthrough -= 1
                self.active = False
                self.finish()
            client.close()

        def start_tunnel():
            logging.info('CONNECTED %s %s',self.request.remote_ip,self.request.path)
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            upstream.write('%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version))
            for k, v in self.request.headers.get_all():
                line = utf8(k) + b(": ") + utf8(v)
                if b('\n') in line:
                    raise ValueError('Newline in header: ' + repr(line)) # Fuck standards
                if options.debug:
                    logging.debug('CLIENT >>> %s',line)
                upstream.write(line+'\r\n')
            upstream.write('\r\n')
            if self.request.body:
                upstream.write(self.request.body)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        upstream = tornado.iostream.IOStream(s)
        upstream.connect((host, int(port)), start_tunnel)


def run_proxy(port, address="", start_ioloop=True):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    app = tornado.web.Application([
        (r'.*', ProxyHandler),
    ])
    app.listen(port,address=address,ssl_options={"certfile":"key.pem","keyfile":"key.pem"})
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()

if __name__ == '__main__':
    parse_command_line()

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    hdlr = logging.FileHandler('secureloli.log')
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr) 

    logging.info("Starting HTTP proxy on %s:%d" % (options.address, options.port))
    run_proxy(options.port,options.address)

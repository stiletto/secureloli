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

from tornado.escape import utf8, _unicode, native_str
from tornado.util import b

__all__ = ['ProxyHandler', 'run_proxy']


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'HEAD'] #, 'CONNECT']
    backend_host = 'bnw.im'
    backend_connect_host = 'bnw.im'
    backend_port = 80
    debug = False

    @tornado.web.asynchronous
    def get(self):
        self.request.headers['X-Scheme'] = "https"
        self.request.headers['X-Forwarded-For'] = self.request.remote_ip
        self.request.headers['Host'] = self.backend_host

        connection = map(lambda s: s.strip().lower(), self.request.headers.get("Connection", "").split(","))
        #print connection,self.request.headers['Connection']
        if 'upgrade' in connection:
            print 'PASS',self.request.remote_ip,self.request.path,self.request.headers['Connection']
            return self.connect()
        else:
            print 'PROXY',self.request.remote_ip,self.request.path

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
                        'Content-Type', 'Location'):
                    v = response.headers.get(header)
                    if v:
                        self.set_header(header, v)
                if response.body:
                    self.write(response.body)
                self.finish()

        assert self.request.path.startswith('/')
        uri = "http://%s:%d%s?%s" % (self.backend_connect_host,self.backend_port,self.request.path,self.request.query)
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

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def head(self):
        return self.get()

    def connect(self):
        host, port = (self.backend_connect_host,self.backend_port)
        client = self.request.connection.stream

        def read_from_client(data):
            if self.debug:
                print 'CLIENT >>', data
            upstream.write(data)

        def read_from_upstream(data):
            if self.debug:
                print 'UPSTREAM >>', data
            client.write(data)

        def client_close(_dummy):
            if self.debug:
                print 'CLIENTCLOSED',self.request.remote_ip,self.request.path
            upstream.close()

        def upstream_close(_dummy):
            if self.debug:
                print 'UPSTREAMCLOSED',self.request.remote_ip,self.request.path
            client.close()

        def start_tunnel():
            print 'CONNECTED',self.request.remote_ip,self.request.path
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            upstream.write('%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version))
            for k, v in self.request.headers.get_all():
                line = utf8(k) + b(": ") + utf8(v)
                if b('\n') in line:
                    raise ValueError('Newline in header: ' + repr(line)) # Fuck standards
                if self.debug:
                    print 'CLIENT >>>',line
                upstream.write(line+'\r\n')
            upstream.write('\r\n')
            if self.request.body:
                upstream.write(self.request.body)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        upstream = tornado.iostream.IOStream(s)
        upstream.connect((host, int(port)), start_tunnel)


def run_proxy(port, start_ioloop=True):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    app = tornado.web.Application([
        (r'.*', ProxyHandler),
    ])
    app.listen(port,ssl_options={"certfile":"key.pem","keyfile":"key.pem"})
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()

if __name__ == '__main__':
    port = 8444
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    print "Starting HTTP proxy on port %d" % port
    run_proxy(port)

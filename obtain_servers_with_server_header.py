# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import requests
import gevent.monkey
from gevent.pool import Pool

# To view the number of servers in the output file:
# cat with-server-header.txt | sort | uniq -c | sort -rn

gevent.monkey.patch_socket()

WORKERS = 100
INPUT = 'list-of-ips.txt'
OUTPUT = 'with-server-header.txt'

REQUIRE_VERSION = True

def get_hosts(f):
    f_url = open(f, 'r')

    hosts = []
    hosts += [host.strip() for host in f_url.readlines()]

    return hosts


def check_urls(urls):
    global output

    def fetch(url):
        response = requests.request('GET', 'http://' + url, timeout=5.0)
        # TODO server version check
        # regex with /num oid
        # TODO replace string with struct (save on disk space)
        # TODO append server banner string to file, 'sort -n' afterwards
        if response.headers._store.has_key('server'):
            if REQUIRE_VERSION:
                # response.headers._store['server'][1] = "apache"
                server = response.headers._store['server'][1].split('/')[:2]
                server[1] = server[1].split()[0]

                if len(server) == 2 and not '' in server:
                    # output.write("%s,%s\n" % (server[0], server[1]))
                    output.write("%s\n" % url)
                    pass
            else:
                output.write("%s\n" % url)

    pool = Pool(WORKERS)
    for url in urls:
        pool.spawn(fetch, url)
    pool.join()


output = open(OUTPUT, 'a+')

hosts = get_hosts(INPUT)

check_urls(hosts)

# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import gevent.monkey
from gevent.pool import Pool
import urllib2

# To view the number of servers in the output file:
# cat with-server-header.txt | sort | uniq -c | sort -rn

gevent.monkey.patch_socket()

WORKERS = 100
INPUT = 'check-for-headers-1000.csv'
OUTPUT = 'with-server-header3.txt'

REQUIRE_VERSION = True


def get_hosts(f):
    f_url = open(f, 'r')

    hosts = []
    hosts += [host.strip() for host in f_url.readlines()]

    return hosts


def check_urls(urls):
    global output

    def fetch(url):
        # response = http.request('GET', 'http://' + url, timeout=5.0)
        # url = '185.85.18.226'
        try:
            response = urllib2.urlopen("http://" + url)
        except Exception as e:
            return

        # response = urllib2.urlopen("http://" + url).read()
        # TODO server version check
        # regex with /num oid
        # TODO replace string with struct (save on disk space)
        # TODO append server banner string to file, 'sort -n' afterwards
        if response.headers.dict.has_key('server'):
            if REQUIRE_VERSION:
                # response.headers._store['server'][1] = "apache"
                server = response.headers.dict['server']
                server_split = server.split('/')

                if len(server_split) > 1 and not '' in server_split[:2]:
                    # output.write("%s,%s\n" % (server[0], server[1]))
                    output.write("%s\n" % url)
                    print "written %s\n" % url
                else:
                    print "skipping %s\n" % url
            else:
                output.write("%s\n" % url)
                print "written %s\n" % url
        else:
            print "skipping %s\n" % url

    pool = Pool(WORKERS)
    for url in urls:
        pool.spawn(fetch, url)
    pool.join()


output = open(OUTPUT, 'a+')
hosts = get_hosts(INPUT)
check_urls(hosts)

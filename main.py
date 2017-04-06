# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import argparse
import csv
import glob
import hashlib
import logging
import os
import pickle
import pprint
import re
import select
import socket
import sys
import time
import urlparse
from operator import itemgetter

import datetime

EXCEPTION_COUNT_MAX = 3

MAX_ATTEMPT = 3
WAIT_TIME = 1

# TODO only print output if yes
PRINT_OUTPUT = 1

NO_RESPONSE = 'NO_RESPONSE'
NO_RESPONSE_CODE = 'NO_RESPONSE_CODE'
NO_RESPONSE_TEXT = 'NONE'

LEXICAL = 'LEXICAL'
SYNTACTIC = 'SYNTACTIC'
SEMANTIC = 'SEMANTIC'
REQUESTS = 'REQUESTS'

DATA_LIST = 'LIST'
DATA_NONE = None

CACHE = 'cache'
BLACKLIST = 'blacklist'
CSV = 'aaa_' + str(datetime.datetime.now()).replace(' ', '_')[:-7] + '.csv'
CSV_VERBOSE = False

HOST_TOTAL = 0

RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

# FORMAT = '%(asctime)s - %(logname)s - %(levelname)7s - %(message)s'
FORMAT = '%(asctime)s - ' + BOLD_SEQ + '%(logname)15s' + RESET_SEQ + \
         ' [%(host_index)d/%(host_total)d] - %(levelname)7s - %(message)s'
logging.basicConfig(stream=sys.stdout, format=FORMAT)
logger = logging.getLogger('fingerprinter')

d = {'host'}

LOGNAME_START = {
    'logname': 'setup',
    'host_index': 0,
    'host_total': 0
}

EXPORT_CSV = True
csv_export = {}


class UrlInfo:
    def __init__(self, url):
        url_parsed = urlparse.urlparse(url)

        if url_parsed.scheme is '':
            self.scheme = 'http'
            self.host = url_parsed.path.split(':')[0]
            self.port = 80 if url_parsed.path.find(':') is -1 else int(url_parsed.path.split(':')[1])
        else:
            self.scheme = url_parsed.scheme
            self.host = url_parsed.netloc.split(':')[0]
            self.port = 80 if url_parsed.netloc.find(':') is -1 else int(url_parsed.netloc.split(':')[1])


class Request:
    def __init__(self, url, host_index, method="GET", local_uri='/', version="1.0"):
        self.url = url
        self.host_index = host_index
        self.method = method
        self.local_uri = local_uri
        self.version = version
        self.headers = [
            ['User-Agent', 'Fingerprinter/1.0']
        ]
        self.body = ''
        self.line_join = '\r\n'
        self.method_line = ''

    def __str__(self):
        method_line = self.method_line
        if not method_line:
            method_line = '%s %s HTTP/%s' % (self.method, self.local_uri, self.version)

        return self.line_join.join([method_line] + self.create_headers_string()) + (2 * self.line_join) + self.body

    def create_headers_string(self):
        return ['%s: %s' % (key, value) for key, value in self.headers]

    def add_header(self, key, value):
        self.headers.append([key, value])

    @property
    def submit(self):
        CACHE_RESPONSE = False

        url_info = UrlInfo(self.url)
        host = url_info.host
        port = url_info.port

        self_hex = hashlib.md5(str(self)).hexdigest()
        d = CACHE + '/' + host + '.' + str(port)
        f = d + '/' + self_hex
        if os.path.isdir(d):
            try:
                if os.path.exists(f):
                    logger.debug("using cached response %s", f, extra={'logname': host, 'host_index': self.host_index, 'host_total': HOST_TOTAL})
                    f_url = open(f, 'rb')
                    response = pickle.load(f_url)
                    f_url.close()

                    if EXPORT_CSV:
                        add_request_response(self, response, url_info)

                    return response
                else:
                    logger.warning("no cache file for %s", f, extra={'logname': host, 'host_index': self.host_index, 'host_total': HOST_TOTAL})
                    CACHE_RESPONSE = True
            except EOFError:
                logger.error("corrupt cached response %s, removing it", f, extra={'logname': host, 'host_index': self.host_index, 'host_total': HOST_TOTAL})
                os.remove(f)
        else:
            os.makedirs(d)
            CACHE_RESPONSE = True

        attempt = 0
        data = ''

        while attempt < MAX_ATTEMPT:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)

            try:
                logger.info("sending request \n%4s%s", ' ', str(self).rstrip(), extra={'logname': host, 'host_index': self.host_index, 'host_total': HOST_TOTAL})
                s.connect((host, port))
                s.settimeout(None)
                s.sendall(str(self))
            except(socket.error, RuntimeError, Exception) as e:
                #self.store_cache_response(str(e), f, host, self_hex)
                raise ValueError(e)

            data = ''

            try:
                while 1:
                    # Only proceed if feedback is received
                    ss = select.select([s], [], [], 1)[0]
                    if not ss:
                        break

                    # Assign the temporary socket pointer to the first socket in the list
                    ss = ss[0]

                    # Store the response for processing if present
                    temp = ss.recv(1024)
                    if not temp:
                        break

                    data += temp
                s.close()
            except(socket.error, RuntimeError, Exception):
                attempt += 1
                time.sleep(WAIT_TIME)
                s.close()
                continue
            break

        if CACHE_RESPONSE:
            self.store_cache_response(data, f, host, self_hex)

        response = Response(data)

        if EXPORT_CSV:
            add_request_response(self, response, url_info)

        return response

    def store_cache_response(self, data, f, host, self_hex):
        logger.debug("caching response to %s", self_hex,
                     extra={'logname': host, 'host_index': self.host_index, 'host_total': HOST_TOTAL})

        f_url = open(f, 'wb')
        pickle.dump(Response(data), f_url, protocol=pickle.HIGHEST_PROTOCOL)
        f_url.close()


class Response:
    def __init__(self, raw_data):
        # TODO takes memory, maybe deprecate
        self.raw_data = raw_data
        self.headers = []
        self.body = ''
        self.__parse(raw_data)

    def __parse(self, data):
        if not data:
            self.response_code = NO_RESPONSE_CODE
            self.response_text = NO_RESPONSE_TEXT
            return

        if not re.search('HTTP/1\.[01] [0-9]{3} [A-Z]{,10}', data):
            self.response_code = NO_RESPONSE_CODE
            self.response_text = NO_RESPONSE_TEXT
            self.body = data
            return

        crlf_index = data.find('\r\n')
        cr_index = data.find('\r')
        line_split = '\r\n'

        if crlf_index == -1 or cr_index < crlf_index:
            line_split = '\n'

        # Obtain all headers
        response_lines = data.split(line_split)

        # Split first header into code and text
        self.response_line = response_lines[0]
        response_line_match = re.search('(HTTP/1\.[01]) ([0-9]{3}) ([^\r\n]*)', data)
        self.response_code, self.response_text = response_line_match.groups()[1:]

        # Obtain body after first empty line
        blank_index = response_lines[:].index('')
        if blank_index == -1:
            blank_index = len(response_lines)

        self.headers = response_lines[1:blank_index]
        self.body = response_lines[blank_index:]

    def has_header(self, name):
        for h in self.headers:
            if h.startswith(name):
                return 1
        return 0

    def header_data(self, name):
        assert (self.has_header(name))
        for h in self.headers:
            if h.startswith(name):
                return h.split(': ', 1)[-1]

    def header_names(self):
        result = []
        for h in self.headers:
            name = h.split(':', 1)[0]
            result.append(name)
        return result

    def return_code(self):
        return self.response_code, self.response_text

    def server_name(self):
        if not self.has_header('Server'):
            return None
        # This cuts off any possible modules but also anything else
        s = self.header_data('Server').split()
        if len(s) > 1:
            return s[0]
        else:
            return s


def add_characteristic(category, name, value, fingerprint, data_type=DATA_NONE):
    if not fingerprint[category].has_key(name):
        # TODO maybe remove data type
        if data_type == 'list':
            value = [value]
        fingerprint[category][name] = value
        return

    if fingerprint[category][name] == value:
        return


def add_request_response(request, response, url_info):
    host = url_info.host + ':' + str(url_info.port)

    if not csv_export.has_key(host):
        csv_export[host] = {}

    csv_export[host][str(request)] = response


def get_characteristics(test_name, response, fingerprint, host, host_index):
    # logger.debug("applying %s", test_name, extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})

    response_code, response_text = response.return_code()
    server_name_claimed = response.server_name()

    if response_code not in [NO_RESPONSE, NO_RESPONSE_CODE]:
        add_characteristic(LEXICAL, response_code, response_text, fingerprint)
        add_characteristic(LEXICAL, 'SERVER_NAME_CLAIMED', server_name_claimed, fingerprint)

    # TODO needed?
    # if test_name.endswith('RANGES'):
    #     return  # only need the code and text

    if test_name.startswith('MALFORMED_'):
        add_characteristic(SEMANTIC, test_name, response_code, fingerprint)

    if response.has_header('Allow'):
        data = response.header_data('Allow')
        add_characteristic(SYNTACTIC, 'ALLOW_ORDER', data, fingerprint)

    if response.has_header('Public'):
        data = response.header_data('Public')
        add_characteristic(SYNTACTIC, 'PUBLIC_ORDER', data, fingerprint)

    if response.has_header('Vary'):
        data = response.header_data('Vary')
        add_characteristic(SYNTACTIC, 'VARY_ORDER', data, fingerprint)

    if response_code not in [NO_RESPONSE_CODE, NO_RESPONSE]:
        header_names = response.header_names()
        add_characteristic(SYNTACTIC, 'HEADER_ORDER', header_names, fingerprint, data_type=DATA_LIST)

    if response.has_header('ETag'):
        data = response.header_data('ETag')
        add_characteristic(SYNTACTIC, 'ETag', data, fingerprint)
    elif response.has_header('Etag'):
        data = response.header_data('Etag')
        add_characteristic(SYNTACTIC, 'ETag', data, fingerprint)


def default_get(host, host_index, fingerprint):
    request = Request(host, host_index)
    response = request.submit
    get_characteristics('default_get', response, fingerprint, host, host_index)


def default_options(host, host_index, fingerprint):
    request = Request(host, host_index, method='OPTIONS')
    response = request.submit
    get_characteristics('default_options', response, fingerprint, host, host_index)


def unknown_method(host, host_index, fingerprint):
    request = Request(host, host_index, method='ABCDEFG')
    response = request.submit
    get_characteristics('unknown_method', response, fingerprint, host, host_index)


def unauthorized_activity(host, host_index, fingerprint):
    activities = ('OPTIONS', 'TRACE', 'GET', 'HEAD', 'DELETE',
                  'PUT', 'POST', 'COPY', 'MOVE', 'MKCOL',
                  'PROPFIND', 'PROPPATCH', 'LOCK', 'UNLOCK',
                  'SEARCH')

    for activity in activities:
        request = Request(host, host_index, method=activity)
        response = request.submit
        get_characteristics('unauthorized_activity_' + activity, response, fingerprint, host, host_index)


def empty_uri(host, host_index, fingerprint):
    request = Request(host, host_index, local_uri='/ABCDEFG')
    response = request.submit
    get_characteristics('empty_uri', response, fingerprint, host, host_index)


def malformed_method(host, host_index, fingerprint):
    malformed_methods = get_malformed_methods()

    for index, method in enumerate(malformed_methods):
        request = Request(host, host_index)
        request.method_line = method
        response = request.submit
        get_characteristics('MALFORMED_' + ('000' + str(index))[-3:], response, fingerprint, host, host_index)


def get_malformed_methods():
    activities = 'GET', 'HEAD', 'POST', 'PUT'

    malformed_methods_list = []

    for activity in activities:
        malformed_methods = (
            activity,
            activity + '/',
            activity + '/1.0',
            activity + ' / HTTP/123.45',
            activity + ' / HTTP/999.99',
            activity + ' / HTP/1.0',
            activity + ' / HTT/1.0',
            activity + ' / HTTP/7.Q',
            activity + ' / HTTP/1.0X',
            activity + ' /abcdefghijklmnopqrstuvwxyz/.. HTTP/1.0',
            activity + ' /./././././././././././././././ HTTP/1.0',
            activity + ' /.. HTTP/1.0',
            activity + '\t/\tHTTP/1.0',
            activity + '\t/\tHTTP/1.0',
            activity + ' / H',
            activity + ' / ' + 'HTTP/' + '1' * 1000 + '.0',
            activity + ' FTP://abcdefghi HTTP/1.0',
            activity + ' C:\ HTTP/1.0',
            ' ' * 1000 + activity + ' / HTTP/1.0',
            '\n' + activity + ' / HTTP/1.0',
        )

        malformed_methods_list += malformed_methods

    malformed_activity_independent = (
        'GET GET GET',
        'HELLO',
        '%47%45%54 / HTTP/1.0',
        'GEX\bT / HTTP/1.0'
    )

    malformed_methods_list += malformed_activity_independent

    return malformed_methods_list


def unavailable_accept(host, host_index, fingerprint):
    request = Request(host, host_index)
    request.add_header('Accept', 'abcd/efgh')
    response = request.submit
    get_characteristics('unavailable_accept', response, fingerprint, host, host_index)


def long_content_length(host, host_index, fingerprint):
    request = Request(host, host_index)
    request.add_header('Content-Length', str(sys.maxint))
    request.body = 'abcdefgh'
    response = request.submit
    get_characteristics('long_content_length', response, fingerprint, host, host_index)


def get_fingerprint(host, host_index, blacklist):
    fingerprint = {
        LEXICAL: {},
        SYNTACTIC: {},
        SEMANTIC: {}
    }

    fingerprint_methods = [default_get, default_options, unknown_method, unauthorized_activity, empty_uri,
                           malformed_method, unavailable_accept, long_content_length]

    for method in fingerprint_methods:
        # logger.debug("processing %s", method.__name__, extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})

        try:
            method(host, host_index, fingerprint)
        except ValueError as e:
            logger.warning("%s", e, extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})

            if method == default_get:
                print "BLACKLISTING"
                update_blacklist(blacklist, host, host_index)
                break



    return fingerprint


def save_fingerprint(args, fingerprint, host):
    url_info = UrlInfo(host)

    # TODO check for file existence and maybe skip querying if found
    d = args.output

    if d[-1:] != '/':
        d += '/'
    f = d + url_info.host + '.' + str(url_info.port)
    f_url = open(f, 'w+')
    pprint.PrettyPrinter(stream=f_url).pprint(fingerprint)
    f_url.close()

    # logger.debug("saved output to %s", f, extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})


def get_known_fingerprints(args):
    if args.gather is False:
        fingerprints = []
        d = args.known

        if d[-1:] != '/':
            d += '/'
        for f in glob.glob(d + '/*'):
            f_file = open(f, 'r')
            f_fingerprint = eval(f_file.read())
            fingerprints.append(f_fingerprint)
            f_file.close()
            logger.debug("loading known fingerprint %s", f, extra=LOGNAME_START)

        return fingerprints
    else:
        return


def get_fingerprint_scores(args, subject, known_fingerprints):
    scores = []

    for known in known_fingerprints:
        similarity = {
            'matches': 0,
            'mismatches': 0,
            'unknowns': 0
        }

        header_match = subject[LEXICAL].has_key('SERVER_NAME_CLAIMED') \
                       and known[LEXICAL].has_key('SERVER_NAME_CLAIMED') \
                       and subject[LEXICAL]['SERVER_NAME_CLAIMED'] == known[LEXICAL]['SERVER_NAME_CLAIMED']

        if header_match and args.lazy:
            certainty = 1
        else:
            similarity = find_similar_lexical(known, similarity, subject)

            similarity = find_similar_syntactic(known, similarity, subject)

            similarity = find_similar_semantic(known, similarity, subject)

            certainty = similarity['matches'] / float(similarity['matches'] + similarity['mismatches'])

        scores.append([known, similarity, certainty])
    return scores


def find_similar_lexical(known, similarity, subject):
    # TODO select appropriate response codes, the more the better
    response_codes = range(200, 220) + \
                     range(300, 320) + \
                     range(400, 420) + \
                     range(500, 520)
    for code in response_codes:
        if known[LEXICAL].has_key(code) and subject[LEXICAL].has_key(code):
            known_text = known[LEXICAL][code]
            subject_text = subject[LEXICAL][code]

            if known_text == '' or subject_text == '':
                similarity['unknowns'] += 1
            elif known_text == subject_text:
                similarity['matches'] += 1
            else:
                similarity['mismatches'] += 1

    return similarity


def find_similar_syntactic(known, similarity, subject):
    similarity = find_similar_allow_order(known, similarity, subject)
    similarity = find_similar_etag(known, similarity, subject)

    return similarity


def find_similar_allow_order(known, similarity, subject):
    known_allows = subject_allows = ''

    if known[SYNTACTIC].has_key('ALLOW_ORDER'):
        known_allows = known[SYNTACTIC]['ALLOW_ORDER']

    if subject[SYNTACTIC].has_key('ALLOW_ORDER'):
        subject_allows = subject[SYNTACTIC]['ALLOW_ORDER']
    if known_allows and subject_allows:
        if known_allows == subject_allows:
            similarity['matches'] += 1
        else:
            similarity['mismatches'] += 1
    else:
        similarity['unknowns'] += 1

    return similarity


def find_similar_etag(known, similarity, subject):
    known_etag = subject_etag = ''
    if known[SYNTACTIC].has_key('ETag'):
        known_etag = known[SYNTACTIC]['ETag']
    if subject[SYNTACTIC].has_key('ETag'):
        subject_etag = subject[SYNTACTIC]['ETag']
    if known_etag == '' or subject_etag == '':
        similarity['unknowns'] += 1
    elif known_etag == subject_etag:
        similarity['matches'] += 1
    else:
        similarity['mismatches'] += 1
    return similarity


def find_similar_semantic(known, similarity, subject):
    # TODO make length based on no. of malform requests instead of hardcoded
    for i in range(len(get_malformed_methods())):
        malformed = 'MALFORMED_' + ('000' + str(i))[-3:]

        if known[SEMANTIC].has_key(malformed):
            known_malformed = known[SEMANTIC][malformed]
            subject_malformed = subject[SEMANTIC][malformed]

            if known_malformed == subject_malformed:
                similarity['matches'] += 1
            else:
                similarity['mismatches'] += 1
        else:
            similarity['unknowns'] += 1

    return similarity


def score_compare(score_a, score_b):
    server_a = score_a[0]
    # matches_a = score_a[1]['matches']
    matches_a = score_a[2]

    server_b = score_b[0]
    # matches_b = score_b[1]['matches']
    matches_b = score_b[2]

    compared = -cmp(matches_a, matches_b)
    if compared != 0:
        return compared
    else:
        return -cmp(server_a, server_b)


def sort_scores(scores):
    if len(scores) is 1:
        return scores

    scores.sort(score_compare)

    return scores


def print_scores(hostname, scores):
    lint = "-" * 80
    print '\n%s\n%-50s\n%-50s   %4s (%4s : %3s : %3s)' % (
        lint, hostname[:50], 'name', 'certainty', 'matches', 'mismatches', 'unknowns')

    for score in scores:
        name = score[0][LEXICAL]['SERVER_NAME_CLAIMED'][:50]
        matches = score[1]['matches']
        mismatches = score[1]['mismatches']
        unknowns = score[1]['unknowns']
        certainty = score[2]

        print '%-50s   %.3f     (%2d : %2d : %2d)' % (name, certainty, matches, mismatches, unknowns)
    print lint


def print_fingerprint(fingerprint, host):
    # logger.debug("output:", extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(fingerprint)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Fingerprint web servers and store them',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=30)
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '-i', '--input',
        help='hostname or IP address',
        dest='input'
    )
    group.add_argument(
        '-f', '--file',
        help='file with line separated hostnames or IP addresses',
        type=argparse.FileType('r'),
        dest='file'
    )

    parser.add_argument(
        '-s', '--save',
        help="directory where output fingerprints are stored",
        dest='output', default='output/'
    )

    parser.add_argument(
        '-k', '--known',
        help="directory where known fingerprints are stored",
        dest='known', default='known/'
    )

    parser.add_argument(
        '-g', '--gather',
        help="only gather data (omit comparing results)",
        action='store_true', default=False
    )

    parser.add_argument(
        '-l', '--lazy',
        help="trust server banners and omit other results if possible",
        action='store_true', default=False
    )

    parser.add_argument(
        '-v', '--verbose',
        help="show verbose statements",
        action="store_const", dest="loglevel", const=logging.INFO,
        default=logging.INFO
    )

    parser.add_argument(
        '-d', '--debug',
        help="show debugging statements",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.INFO
    )

    return parser.parse_args()


def start_logger(args):
    logger.setLevel(args.loglevel)
    logger.info('starting session', extra=LOGNAME_START)


def get_hosts(args):
    hosts = []
    if args.input is not None:
        hosts.append(args.input)
    else:
        hosts += [host.strip() for host in args.file.readlines()]

    return hosts


def open_blacklist_file(blacklist_file):
    return open(blacklist_file, 'a')


def update_blacklist(blacklist_handler, host, host_index):
    blacklist_handler.write(host + '\n')
    logger.info('host added to blacklist', extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})


def close_blacklist_file(blacklist_handler):
    blacklist_handler.close()


def process_host(args, host, host_index, known_fingerprints, blacklist):
    f = get_fingerprint(host, host_index, blacklist)

    save_fingerprint(args, f, host)

    if args.gather is False:
        scores = get_fingerprint_scores(args, f, known_fingerprints)

        scores = sort_scores(scores)

        print_scores(host, scores)


def process_hosts(args, hosts, known_fingerprints, blacklist):
    # from gevent.pool import Pool
    # WORKERS = 100
    #
    # pool = Pool(WORKERS)
    # for index, host in enumerate(hosts):
    #     try:
    #         logger.info("processing host (%s/%s)", index + 1, len(hosts), extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})
    #         pool.spawn(process_host, args, host, known_fingerprints)
    #     except ValueError as e:
    #         logger.error(e, extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})
    #
    # pool.join()
    global HOST_TOTAL

    with open(BLACKLIST) as f:
        blacklist_hosts = f.readlines()

    HOST_TOTAL = len(hosts)

    for host_index, host in enumerate(hosts):
        try:
            host_index += 1
            logger.info("processing host (%s/%s)", host_index, len(hosts), extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})


            if host + '\n' not in blacklist_hosts:
                process_host(args, host, host_index, known_fingerprints, blacklist)
            else:
                logger.error('host is blacklisted', extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})
        except ValueError as e:
            logger.error(e, extra={'logname': host, 'host_index': host_index, 'host_total': HOST_TOTAL})


def extract_banner_from_requests(requests):
    banner = ''
    for request, response in requests.iteritems():
        if not banner:
            banner = next((header for header in response.headers if "Server" in header), '')
        else:
            break

    return banner


def csv_exporter(dict):
    f = open(CSV, 'w+')
    writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

    top = ['method']

    results = {}

    for host, requests in dict.iteritems():
        top.append(host)

        response_banner_key = 'BANNER_REPORTED'
        response_banner_value = extract_banner_from_requests(requests)
        results = update_csv_results(response_banner_key, response_banner_value, results)

        for request, response in requests.iteritems():
            response_code_key = request.rstrip() + ' RESPONSE_CODE'
            response_code_variable = response.response_code
            results = update_csv_results(response_code_key, response_code_variable, results)

            response_text_key = request.rstrip() + ' RESPONSE_TEXT ' + response.response_code
            response_text_variable = response.response_text
            results = update_csv_results(response_text_key, response_text_variable, results)
        pass

    top.append('unique values')

    number_of_columns = len(top)

    if CSV_VERBOSE:
        writer.writerow(top)
    else:
        writer.writerow(['method', 'count', 'unique responses'])

    results_sorted = []

    for request, responses in results.iteritems():
        unique_values = list(set(responses))

        set(responses)

        # Padding for correct placement of unique value counter
        # while len(responses) < number_of_columns - 2:
        #     responses.append('')

        row = [request.rstrip()]
        row.append(len(unique_values))
        row.extend(unique_values)

        # responses[0] = request.rstrip()
        # responses.append(request.rstrip())
        # responses.append(len(unique_values))
        # responses.extend(unique_values)

        # results_sorted.append(responses)
        results_sorted.append(row)

        # writer.writerow(responses)

    res = sorted(results_sorted, key=itemgetter(1), reverse=True)

    for row in res:
        if CSV_VERBOSE:
            writer.writerow(row)
        else:
            # row_short = [row[0], row[-1]]
            writer.writerow(row)

    f.close()


def update_csv_results(key, value, results):
    if not results.has_key(key):
        results[key] = []

    results[key].append(value)
    return results


if __name__ == '__main__':
    args = parse_arguments()

    # TODO debug
    # args.gather = True
    # args.loglevel = logging.INFO

    start_logger(args)

    hosts = get_hosts(args)

    blacklist = open_blacklist_file(BLACKLIST)

    hosts = hosts[-10:-1]

    known_fingerprints = get_known_fingerprints(args)

    process_hosts(args, hosts, known_fingerprints, blacklist)

    csv_exporter(csv_export)

    close_blacklist_file(blacklist)

    # TODO
    # - compare against predefined footprints
    # - check if hostname/port already exists in output file
    # - create a counter per predefined footprin?

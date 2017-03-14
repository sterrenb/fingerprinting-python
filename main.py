# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#
import sys, urlparse, argparse, socket, select, time, re, pprint, glob, logging, pickle, os, hashlib

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

DATA_LIST = 'LIST'
DATA_NONE = None

CACHE = 'cache'

FORMAT = '%(asctime)s - %(logname)s - %(levelname)7s - %(message)s'
logging.basicConfig(stream=sys.stdout, format=FORMAT)
logger = logging.getLogger('fingerprinter')

d = {'host'}

LOGNAME_START = {'logname': 'setup'}


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
    def __init__(self, url, method="GET", local_uri='/', version="1.0"):
        self.url = url
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
            # print "found host directory"
            if os.path.exists(f):
                # logger.debug("using cached response %s", f, extra={'logname': host + ':' + str(port)})
                f_url = open(f, 'rb')
                response = pickle.load(f_url)
                f_url.close()
                return response
            else:
                CACHE_RESPONSE = True
        else:
            os.makedirs(d)
            CACHE_RESPONSE = True

        attempt = 0
        data = ''

        while attempt < MAX_ATTEMPT:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                s.connect((host, port))
                s.send(str(self))
            except(socket.error, RuntimeError, Exception) as e:
                raise ValueError(e)

            data = ''

            try:
                while 1:
                    # Only proceed if feedback is received
                    ss = select.select([s], [], [], 10)[0]
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
            f_url = open(f, 'wb')
            pickle.dump(Response(data), f_url, protocol=pickle.HIGHEST_PROTOCOL)
            f_url.close()

            # logger.debug("caching response", extra={'logname': host + ':' + str(port)})

        return Response(data)


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
        return self.header_data('Server')


def add_characteristic(category, name, value, fingerprint, data_type=DATA_NONE):
    if not fingerprint[category].has_key(name):
        # TODO maybe remove data type
        if data_type == 'list':
            value = [value]
        fingerprint[category][name] = value
        return

    if fingerprint[category][name] == value:
        return


def get_characteristics(test_name, response, fingerprint, host):
    logger.debug("applying %s", test_name, extra={'logname': host})

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


def default_get(host, fingerprint):
    request = Request(host)
    response = request.submit
    get_characteristics('default_get', response, fingerprint, host)


def default_options(host, fingerprint):
    request = Request(host, method='OPTIONS')
    response = request.submit
    get_characteristics('default_options', response, fingerprint, host)


def unknown_method(host, fingerprint):
    request = Request(host, method='ABCDEFG')
    response = request.submit
    get_characteristics('unknown_method', response, fingerprint, host)


def unauthorized_activity(host, fingerprint):
    activities = ('OPTIONS', 'TRACE', 'GET', 'HEAD', 'DELETE',
                  'PUT', 'POST', 'COPY', 'MOVE', 'MKCOL',
                  'PROPFIND', 'PROPPATCH', 'LOCK', 'UNLOCK',
                  'SEARCH')

    for activity in activities:
        request = Request(host, method=activity)
        response = request.submit
        get_characteristics('unauthorized_activity_' + activity, response, fingerprint, host)


def empty_uri(host, fingerprint):
    request = Request(host, local_uri='/ABCDEFG')
    response = request.submit
    get_characteristics('empty_uri', response, fingerprint, host)


def malformed_method(host, fingerprint):
    # TODO also use  other activities like HEAD, PUT etc, loop over activity
    # Great increase in requests though

    activity = 'GET'
    malformed_methods = (
        activity,
        activity + '/',
        activity + '/1.0',
        activity + ' / HTTP/123.45',
        activity + ' / HTP/1.0',
        activity + ' / HTT/1.0',
        'I AM METHOD'
    )

    for index, method in zip(range(len(malformed_methods)), malformed_methods):
        request = Request(host)
        request.method_line = method
        response = request.submit
        get_characteristics('MALFORMED_' + ('000' + str(index))[-3:], response, fingerprint, host)


def unavailable_accept(host, fingerprint):
    request = Request(host)
    request.add_header('Accept', 'abcd/efgh')
    response = request.submit
    get_characteristics('unavailable_accept', response, fingerprint, host)


def long_content_length(host, fingerprint):
    request = Request(host)
    request.add_header('Content-Length', str(sys.maxint))
    request.body = 'abcdefgh'
    response = request.submit
    get_characteristics('long_content_length', response, fingerprint, host)


def get_fingerprint(host):
    fingerprint = {
        LEXICAL: {},
        SYNTACTIC: {},
        SEMANTIC: {}
    }

    fingerprint_methods = [default_get, default_options, unknown_method, unauthorized_activity, empty_uri, malformed_method, unavailable_accept, long_content_length]

    for method in fingerprint_methods:
        logger.info("processing %s", method.__name__, extra={'logname': host})
        method(host, fingerprint)

    # TODO list any possible methods here
    # default_get(host, fingerprint)
    # default_options(host, fingerprint)
    # unknown_method(host, fingerprint)
    # unauthorized_activity(host, fingerprint)
    # empty_uri(host, fingerprint)
    # malformed_method(host, fingerprint)
    # unavailable_accept(host, fingerprint)
    # long_content_length(host, fingerprint)

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

    logger.info("saved output to %s", f, extra={'logname': host})


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


def get_fingerprint_scores(subject, known_fingerprints):
    scores = []

    for known in known_fingerprints:
        similarity = {
            'matches': 0,
            'mismatches': 0,
            'unknowns': 0
        }

        similarity = find_similar_lexical(known, similarity, subject)

        similarity = find_similar_syntactic(known, similarity, subject)

        similarity = find_similar_semantic(known, similarity, subject)

        scores.append([known, similarity])
    return scores


def find_similar_lexical(known, similarity, subject):
    # TODO select appropriate response codes, the more the better
    response_codes = ('200',
                      '400', '404', '405',)

    for code in response_codes:
        known_text = subject_text = ''

        if known[LEXICAL].has_key(code):
            known_text = known[LEXICAL][code]

        if subject[LEXICAL].has_key(code):
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
    for i in range(7):
        malformed = 'MALFORMED_' + ('000' + str(i))[-3:]
        known_malformed = known[SEMANTIC][malformed]
        subject_malformed = subject[SEMANTIC][malformed]

        if known_malformed == subject_malformed:
            similarity['matches'] += 1
        else:
            similarity['mismatches'] += 1

    return similarity


def score_compare(score_a, score_b):
    server_a = score_a[0]
    matches_a = score_a[1]['matches']

    server_b = score_b[0]
    matches_b = score_b[1]['matches']

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
    print '\n%s\n%-50s\n%-40s   %4s : %3s : %3s' % (lint, hostname[:50], 'name', 'matches', 'mismatches', 'unknowns')

    for score in scores:
        name = score[0][LEXICAL]['SERVER_NAME_CLAIMED'][:50]
        matches = score[1]['matches']
        mismatches = score[1]['mismatches']
        unknowns = score[1]['unknowns']

        print '%-50s   %3d : %3d : %3d' % (name, matches, mismatches, unknowns)
    print lint


def print_fingerprint(fingerprint, host):
    logger.debug("output:", extra={'logname':host})
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
        '-d', '--debug',
        help="show debugging statements",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARNING
    )
    parser.add_argument(
        '-v', '--verbose',
        help="show verbose statements",
        action="store_const", dest="loglevel", const=logging.INFO,
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


def process_host(args, host, known_fingerprints):
    f = get_fingerprint(host)

    save_fingerprint(args, f, host)

    if args.loglevel is logging.DEBUG: print_fingerprint(f, host)

    if args.gather is False:
        scores = get_fingerprint_scores(f, known_fingerprints)

        scores = sort_scores(scores)

        print_scores(host, scores)


def process_hosts(args, hosts, known_fingerprints):
    for host in hosts:
        try:
            process_host(args, host, known_fingerprints)
        except ValueError as e:
            logger.error(e, extra={'logname': host})


if __name__ == '__main__':
    args = parse_arguments()

    # TODO debug
    # args.gather = True
    # args.loglevel = logging.INFO

    start_logger(args)

    hosts = get_hosts(args)

    known_fingerprints = get_known_fingerprints(args)

    process_hosts(args, hosts, known_fingerprints)

    # TODO
    # - compare against predefined footprints
    # - check if hostname/port already exists in output file
    # - create a counter per predefined footprin?

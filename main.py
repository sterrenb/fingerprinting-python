# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#
import sys, urlparse, argparse, socket, select, time, re, pprint, glob

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

    def submit(self):
        url_info = UrlInfo(self.url)
        host = url_info.host
        port = url_info.port

        attempt = 0
        data = ''

        while attempt < MAX_ATTEMPT:
            if globals()['verbose'] and attempt > 0: print "attempt: ", attempt

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                s.connect((host, port))
                s.send(str(self))
            except(socket.error, RuntimeError, Exception) as e:
                if globals()['verbose']: print "submit:", e.strerror
                break

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


def get_characteristics(test_name, response, fingerprint):
    if globals()['verbose']: print "applying", test_name

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


def default_get(url, fingerprint):
    request = Request(url)
    response = request.submit()
    get_characteristics('default_get', response, fingerprint)


def default_options(url, fingerprint):
    request = Request(url, method='OPTIONS')
    response = request.submit()
    get_characteristics('default_options', response, fingerprint)


def unknown_method(url, fingerprint):
    request = Request(url, method='ABCDEFG')
    response = request.submit()
    get_characteristics('unknown_method', response, fingerprint)


def unauthorized_activity(url, fingerprint):
    activities = ('OPTIONS', 'TRACE', 'GET', 'HEAD', 'DELETE',
                  'PUT', 'POST', 'COPY', 'MOVE', 'MKCOL',
                  'PROPFIND', 'PROPPATCH', 'LOCK', 'UNLOCK',
                  'SEARCH')

    for activity in activities:
        request = Request(url, method=activity)
        response = request.submit()
        get_characteristics('unauthorized_activity_' + activity, response, fingerprint)


def empty_uri(url, fingerprint):
    request = Request(url, local_uri='/ABCDEFG')
    response = request.submit()
    get_characteristics('empty_uri', response, fingerprint)


def malformed_method(url, fingerprint):
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
        request = Request(url)
        request.method_line = method
        response = request.submit()
        get_characteristics('MALFORMED_' + ('000' + str(index))[-3:], response, fingerprint)


def unavailable_accept(url, fingerprint):
    request = Request(url)
    request.add_header('Accept', 'abcd/efgh')
    response = request.submit()
    get_characteristics('unavailable_accept', response, fingerprint)


def long_content_length(url, fingerprint):
    request = Request(url)
    request.add_header('Content-Length', str(sys.maxint))
    request.body = 'abcdefgh'
    response = request.submit()
    get_characteristics('long_content_length', response, fingerprint)


def get_fingerprint(url):
    fingerprint = {
        LEXICAL: {},
        SYNTACTIC: {},
        SEMANTIC: {}
    }

    # TODO list any possible methods here
    default_get(url, fingerprint)
    default_options(url, fingerprint)
    unknown_method(url, fingerprint)
    unauthorized_activity(url, fingerprint)
    empty_uri(url, fingerprint)
    malformed_method(url, fingerprint)
    # unavailable_accept(url, fingerprint)
    # long_content_length(url, fingerprint)

    return fingerprint


def save_fingerprint(fingerprint, url, directory):
    url_info = UrlInfo(url)

    # TODO check for file existence and maybe skip querying if found
    if directory[-1:] != '/':
        directory += '/'
    f = directory + url_info.host + '.' + str(url_info.port)
    f_url = open(f, 'w+')
    pprint.PrettyPrinter(stream=f_url).pprint(fingerprint)
    f_url.close()

    if globals()['verbose']: print "Output saved to", f


def get_fingerprints_from_storage(directories):
    fingerprints = []

    for d in directories:
        if d[-1:] != '/':
            d += '/'
        for f in glob.glob(d + '/*'):
            f_file = open(f, 'r')
            f_fingerprint = eval(f_file.read())
            fingerprints.append(f_fingerprint)
            f_file.close()
            if globals()['verbose']: print "Loading known fingerprint", f

    return fingerprints


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
    print '- %-50s\n%-40s   %4s : %3s : %3s' % (hostname[:50], 'name', 'matches', 'mismatches', 'unknowns')

    for score in scores:
        name = score[0][LEXICAL]['SERVER_NAME_CLAIMED'][:50]
        matches = score[1]['matches']
        mismatches = score[1]['mismatches']
        unknowns = score[1]['unknowns']

        print '%-50s   %3d : %3d : %3d' % (name, matches, mismatches, unknowns)


def print_fingerprint(fingerprint):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(fingerprint)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find fingerprints for web servers and store them',
                                     prog='prog',
                                     formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=27)
                                     )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-i', '--input', dest='input', help='A hostname or IP address')
    group.add_argument('-f', '--file', type=argparse.FileType('r'), dest='file', help='A file with line separated '
                                                                              'hostnames or IP addresses')

    parser.add_argument('-s', '--save', dest='output', default='output/', help="The directory where output "
                                                                                  "fingerprints are stored")

    parser.add_argument('-k', '--known', dest='known', default='known/', help="The directory where known "
                                                                                       "fingerprints are stored")

    parser.add_argument('-g', '--gather', action='store_true', default=False, help="Only gather data "
                                                                                   "(omit comparing results "
                                                                                   "or saving output)")

    parser.add_argument('-v', '--verbose', action='store_true', default=False, help="Show verbose output")


    # TODO bad practice with globals
    globals().update(parser.parse_args().__dict__)

    hosts = []
    if globals()['input'] is not None:
        hosts.append(globals()['input'])
    else:
        hosts += [host.strip() for host in globals()['file'].readlines()]

    if globals()['gather'] is False:
        fingerprints_storage = get_fingerprints_from_storage([globals()['known']])

    for host in hosts:
        f = get_fingerprint(host)

        if globals()['verbose']: print_fingerprint(f)

        if globals()['gather'] is False:
            scores = get_fingerprint_scores(f, fingerprints_storage)

            scores = sort_scores(scores)

            print_scores(host, scores)

            save_fingerprint(f, host, globals()['output'])


    # TODO
    # - compare against predefined footprints
    # - check if hostname/port already exists
    # - multiple URL's
    # - create a counter

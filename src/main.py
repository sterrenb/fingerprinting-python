# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import glob
import re
import sys

import time

from src.io.storage import get_request_items, store_fingerprint, get_number_of_malformed_requests
from static import variables
from static.arguments import parse_arguments
from static.blacklist import Blacklist
from static.logger import setup_logger, LOGNAME_START

from src.exchange.http import Request, UrlInfo, submit_string
from src.static.constants import NO_RESPONSE_CODE, DATA_NONE, LEXICAL, SEMANTIC, SYNTACTIC, DATA_LIST, KNOWN, \
    SERVER_NAMES

logger = setup_logger()

global host_total

def add_characteristic(category, name, value, fingerprint, data_type=DATA_NONE):
    if not fingerprint[category].has_key(name):
        # TODO maybe remove data type
        if data_type == 'list':
            value = [value]
        fingerprint[category][name] = value
        return

    if fingerprint[category][name] == value:
        return


def get_characteristics(test_name, response, fingerprint, host, host_index, NO_RESPONSE=None):
    # logger.debug("applying %s", test_name, extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})

    response_code, response_text = response.return_code()
    server_name_claimed = response.server_name()

    if response_code not in [NO_RESPONSE, NO_RESPONSE_CODE]:
        add_characteristic(LEXICAL, response_code, response_text, fingerprint)
        add_characteristic(LEXICAL, 'SERVER_NAME_CLAIMED', server_name_claimed, fingerprint)

    # nginx 404 test
    # if response_code == '404':
    #     server_name_404 = get_server_name_404(response)
    #     if len(server_name_404) > 0:
    #         add_characteristic(LEXICAL, 'SERVER_NAME_404', server_name_404, fingerprint)


    if test_name.startswith('malformed_'):
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
    request = Request(host, host_index, logger)
    response = request.submit

    if response.response_code == NO_RESPONSE_CODE:
        raise ValueError('default_get failed')
    else:
        get_characteristics('default_get', response, fingerprint, host, host_index)


def default_options(host, host_index, fingerprint):
    request = Request(host, host_index, logger, method='OPTIONS')
    response = request.submit
    get_characteristics('default_options', response, fingerprint, host, host_index)


def unknown_method(host, host_index, fingerprint):
    request = Request(host, host_index, logger, method='ABCDEFG')
    response = request.submit
    get_characteristics('unknown_method', response, fingerprint, host, host_index)


def unauthorized_activity(host, host_index, fingerprint):
    activities = ('OPTIONS', 'TRACE', 'GET', 'HEAD', 'DELETE',
                  'PUT', 'POST', 'COPY', 'MOVE', 'MKCOL',
                  'PROPFIND', 'PROPPATCH', 'LOCK', 'UNLOCK',
                  'SEARCH')

    for activity in activities:
        request = Request(host, host_index, logger, method=activity)
        response = request.submit
        get_characteristics('unauthorized_activity_' + activity, response, fingerprint, host, host_index)


def empty_uri(host, host_index, fingerprint):
    request = Request(host, host_index, logger, local_uri='/ABCDEFG')
    response = request.submit
    get_characteristics('empty_uri', response, fingerprint, host, host_index)


def malformed_method(host, host_index, fingerprint):
    malformed_methods = get_malformed_methods()

    for index, method in enumerate(malformed_methods):
        request = Request(host, host_index, logger)
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
    request = Request(host, host_index, logger)
    request.add_header('Accept', 'abcd/efgh')
    response = request.submit
    get_characteristics('unavailable_accept', response, fingerprint, host, host_index)


def long_content_length(host, host_index, fingerprint):
    request = Request(host, host_index, logger)
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

    url_info = UrlInfo(host)

    request_items = get_request_items()
    for name, request_string in request_items.iteritems():
        try:
            response = submit_string(request_string, name, url_info, host_index, logger)
            get_characteristics(name, response, fingerprint, host, host_index)
        except ValueError as e:
            logger.warning("%s", e,
                           extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})

    return fingerprint

    # TODO deprecate
    fingerprint_methods = [default_get, default_options, unknown_method, unauthorized_activity, empty_uri,
                           malformed_method, unavailable_accept, long_content_length]

    for method in fingerprint_methods:
        # logger.debug("processing %s", method.__name__, extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})

        try:
            logger.debug('applying method %s', method.__name__,
                         extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})
            method(host, host_index, fingerprint)
        except ValueError as e:
            logger.warning("%s", e,
                           extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})

            if method == default_get:
                blacklist.insert(host)
                logger.info('host added to blacklist',
                            extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})
                break

    return fingerprint


def get_known_fingerprints(args):
    if args.gather is False:
        fingerprints = []
        directories = [args.known, 'data/output']


        for directory in directories:
            for filepath in glob.glob(directory + '/*'):
                logger.debug("loading fingerprint %s", filepath, extra=LOGNAME_START)
                with open(filepath, 'r') as file_handler:
                    f_fingerprint = eval(file_handler.read())
                    fingerprints.append(f_fingerprint)

        return fingerprints


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

            matches = similarity['matches']
            total = float(similarity['matches'] + similarity['mismatches'])
            certainty = matches / total if total > 0 else 0

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
    # similarity = find_similar_etag(known, similarity, subject)

    return similarity


def find_similar_allow_order(known, similarity, subject):
    known_allows = subject_allows = ''

    if known[SYNTACTIC].has_key('ALLOW_ORDER'):
        known_allows = known[SYNTACTIC]['ALLOW_ORDER']
    else:
        return similarity

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
    for i in range(get_number_of_malformed_requests()):
        malformed = 'malformed_' + str(i)

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
        a = score[0]
        b = score[0][LEXICAL]
        # c = score[0][LEXICAL]['SERVER_NAME_CLAIMED']
        name = score[0][LEXICAL]['SERVER_NAME_CLAIMED'] if score[0][LEXICAL].has_key('SERVER_NAME_CLAIMED') else 'NO_BANNER'
        matches = score[1]['matches']
        mismatches = score[1]['mismatches']
        unknowns = score[1]['unknowns']
        certainty = score[2]

        print '%-50s   %.3f     (%2d : %2d : %2d)' % (name, certainty, matches, mismatches, unknowns)
    print lint


def get_hosts(args):
    hosts = []
    if args.input is not None:
        hosts.append(args.input)
    else:
        hosts += [host.strip() for host in args.file.readlines()]

    return hosts


def process_host(args, host, host_index, known_fingerprints, blacklist):
    f = get_fingerprint(host, host_index, blacklist)

    url_info = UrlInfo(host)

    if SERVER_NAMES is True:
        banner = f[LEXICAL]['SERVER_NAME_CLAIMED']
        if isinstance(banner, basestring):
            filename = banner.split()[0]
        else:
            filename = banner[0].split()[0]

        filename = filename.replace('/', '_')

        directory = KNOWN
    else:
        if url_info.port != 80:
            filename = url_info.host + ':' + str(url_info.port)
        else:
            filename = url_info.host

        directory = args.output

    store_fingerprint(directory, f, filename)

    if args.gather is False:
        scores = get_fingerprint_scores(args, f, known_fingerprints)

        scores = sort_scores(scores)

        print_scores(host, scores)


def process_hosts(args, hosts, known_fingerprints, blacklist):
    blacklist_hosts = blacklist.get_hosts()

    for host_index, host in enumerate(hosts):
        try:
            host_index += 1
            logger.info("processing host (%s/%s)", host_index, len(hosts),
                        extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})

            if host not in blacklist_hosts:
                process_host(args, host, host_index, known_fingerprints, blacklist)
            else:
                logger.warning('host is blacklisted',
                               extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})
        except ValueError as e:
            logger.error(e, extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})


if __name__ == '__main__':
    try:
        args = parse_arguments()

        logger = setup_logger(args)

        hosts = get_hosts(args)

        variables.init(len(hosts))

        blacklist = Blacklist()

        # hosts = hosts[-500:]
        # hosts = [hosts[1]]

        variables.host_total = len(hosts)

        known_fingerprints = get_known_fingerprints(args)

        process_hosts(args, hosts, known_fingerprints, blacklist)

        print "NOW!!!"

        time.sleep(50)

        # Request.exporter.generate_output_file()
    except KeyboardInterrupt:
        Request.exporter.generate_output_file()
        sys.exit()

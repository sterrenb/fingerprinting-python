# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#
import fnmatch
import hashlib
import logging
import os
import pickle
import pprint
import sys

from src.static import variables
from src.static.constants import CACHE, REQUESTS

logger = logging.getLogger('root')


def store_cache_response(request, response, host, port, host_index):
    filepath = get_filepath_for_request(request, host, port)

    logger.debug("caching response to %s", filepath,
                 extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})

    file_handler = open(filepath, 'wb')
    pickle.dump(response, file_handler, protocol=pickle.HIGHEST_PROTOCOL)
    file_handler.close()


def store_cache_response_string(request_string, response, host, port, host_index):
    filepath = get_filepath_for_request_string(request_string, host, port)

    logger.debug("caching response to %s", filepath,
                 extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})

    file_handler = open(filepath, 'wb')
    pickle.dump(response, file_handler, protocol=pickle.HIGHEST_PROTOCOL)
    file_handler.close()


def get_cache_response_from_request(request, host, port, url_info, host_index):
    directory = get_directory_for_host(host, port)
    filepath = get_filepath_for_request(request, host, port)

    if os.path.isdir(directory):
        try:
            if os.path.exists(filepath):
                # logger.debug("using cached response %s", filepath,
                #              extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})
                f_url = open(filepath, 'rb')
                response = pickle.load(f_url)
                f_url.close()

                return response
            else:
                raise IOError('file not found', filepath)
        except EOFError:
            raise ValueError('corrupt cache file', filepath)
    else:
        raise IOError('directory not found', directory)


def get_cache_response_from_request_string(request_string, host, port, url_info, host_index):
    directory = get_directory_for_host(host, port)
    filepath = get_filepath_for_request_string(request_string, host, port)

    if os.path.isdir(directory):
        try:
            if os.path.exists(filepath):
                logger.debug("using cached response %s", filepath,
                             extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})
                f_url = open(filepath, 'rb')

                from src.exchange import http
                sys.modules['http'] = http
                response = pickle.load(f_url)
                f_url.close()

                return response
            else:
                raise IOError('file not found', filepath)
        except EOFError:
            raise ValueError('corrupt cache file', filepath)
    else:
        raise IOError('directory not found', directory)


def store_fingerprint(args, fingerprint, url_info):
    directory = args.output

    if directory[-1:] != '/':
        directory += '/'
    filepath = directory + url_info.host + '.' + str(url_info.port)

    with open(filepath, 'w') as file_handler:
        pprint.PrettyPrinter(stream=file_handler).pprint(fingerprint)


def store_requests(requests):
    for request in requests:
        filepath = os.path.join(REQUESTS, request.name)

        if not os.path.exists(os.path.dirname(filepath)):
            os.makedirs(os.path.dirname(filepath))

        with open(filepath, 'w') as file_handler:
            file_handler.write(str(request))

            logger.info("stored request to %s", filepath,
                        extra={'logname': 'None', 'host_index': 0, 'host_total': 0})


def get_request_items():
    request_items = {}

    for root, directories, filenames in os.walk(REQUESTS):
        for filename in fnmatch.filter(filenames, '*'):
            if filename == '.keep':
                continue

            filepath = os.path.join(root, filename)

            with open(filepath, 'r') as file_handler:
                filename = os.path.basename(filepath)
                request = file_handler.read()
                request_items[filename] = request

    return request_items


def remove_cache_file_for_request(request, host, port):
    filepath = get_filepath_for_request(request, host, port)
    os.remove(filepath)


def remove_cache_file_for_request_string(request_string, host, port):
    filepath = get_filepath_for_request_string(request_string, host, port)
    os.remove(filepath)


def create_cache_directory_for_host(host, port):
    try:
        directory = get_directory_for_host(host, port)
        os.makedirs(directory)
    except OSError:
        pass


def get_directory_for_host(host, port):
    return CACHE + '/' + host + '.' + str(port)


def get_filepath_for_request(request, host, port):
    filename = hashlib.md5(str(request)).hexdigest()
    directory = CACHE + '/' + host + '.' + str(port)
    return directory + '/' + filename


def get_filepath_for_request_string(request_string, host, port):
    filename = hashlib.md5(request_string).hexdigest()
    directory = CACHE + '/' + host + '.' + str(port)
    return directory + '/' + filename

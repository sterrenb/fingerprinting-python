# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import hashlib
import logging
import os
import pickle

import variables
from constants import CACHE

logger = logging.getLogger('root')


def store_cache_response(request, response, host, port, host_index):
    filepath = get_filepath_for_request(request, host, port)

    logger.debug("caching response to %s", filepath,
                 extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})

    file_handler = open(filepath, 'wb')
    pickle.dump(response, file_handler, protocol=pickle.HIGHEST_PROTOCOL)
    file_handler.close()


def get_cache_response(request, host, port, url_info, host_index):
    directory = get_directory_for_host(host, port)
    filepath = get_filepath_for_request(request, host, port)

    if os.path.isdir(directory):
        try:
            if os.path.exists(filepath):
                logger.debug("using cached response %s", filepath,
                             extra={'logname': host, 'host_index': host_index, 'host_total': variables.host_total})
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


def remove_cache_file_for_request(request, host, port):
    filepath = get_filepath_for_request(request, host, port)
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
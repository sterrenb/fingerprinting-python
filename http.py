# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import re
import socket
import urlparse
import logging
import time
import select

import variables
from export import add_request_response_to_csv
from constants import EXPORT_CSV, NO_RESPONSE_CODE, NO_RESPONSE_TEXT, CACHE, PAUSE_TIME_AFTER_TIMEOUT, \
    MAX_ATTEMPTS_PER_HOST
from storage import store_cache_response, get_cache_response, remove_cache_file_for_request, \
    create_cache_directory_for_host

logger = logging.getLogger('root')


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
        url_info = UrlInfo(self.url)
        host = url_info.host
        port = url_info.port

        try:
            response = get_cache_response(self, host, port, url_info, self.host_index)

            if EXPORT_CSV:
                add_request_response_to_csv(self, response, url_info)

            return response
        except ValueError as e:
            logger.error("cache read error: %s", e.args,
                         extra={'logname': host, 'host_index': self.host_index, 'host_total': variables.host_total})
            remove_cache_file_for_request(self, host, port)
        except IOError as e:
            # logger.error("cache read error: %s", e.args,
            #              extra={'logname': host, 'host_index': self.host_index, 'host_total': variables.host_total})
            create_cache_directory_for_host(host, port)

        attempt = 0
        data = ''

        while attempt < MAX_ATTEMPTS_PER_HOST:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)

            try:
                logger.info("sending request \n%4s%s", ' ', str(self).rstrip(),
                            extra={'logname': host, 'host_index': self.host_index, 'host_total': variables.host_total})
                s.connect((host, port))
                s.settimeout(None)
                s.sendall(str(self))
            except(socket.error, RuntimeError, Exception) as e:
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
                time.sleep(PAUSE_TIME_AFTER_TIMEOUT)
                s.close()
                continue
            break

        response = Response(data)

        store_cache_response(self, response, host, port, self.host_index)

        if EXPORT_CSV:
            add_request_response_to_csv(self, response, url_info)

        return response


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

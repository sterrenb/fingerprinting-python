# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import sys

from src.exchange.http import Request
from src.io.storage import store_requests


class RequestGenerator:
    def __init__(self):
        pass

    def create_requests(self):
        host = 'host'
        host_index = 0
        requests = []

        methods = [self.default_get, self.default_options, self.unknown_method, self.unauthorized_activity,
                   self.empty_uri, self.malformed_method, self.unavailable_accept, self.long_content_length]

        [requests.extend(method(host, host_index, None)) for method in methods]

        store_requests(requests)


    @staticmethod
    def default_get(host, host_index, logger):
        return [Request(host, host_index, logger, name='default_get')]

    @staticmethod
    def default_options(host, host_index, logger):
        return [Request(host, host_index, logger, method='OPTIONS', name='default_options')]

    @staticmethod
    def unknown_method(host, host_index, logger):
        return [Request(host, host_index, logger, method='ABCDEFG', name='unknown_method')]

    @staticmethod
    def unauthorized_activity(host, host_index, logger):
        requests = []
        activities = ('OPTIONS', 'TRACE', 'GET', 'HEAD', 'DELETE',
                      'PUT', 'POST', 'COPY', 'MOVE', 'MKCOL',
                      'PROPFIND', 'PROPPATCH', 'LOCK', 'UNLOCK',
                      'SEARCH')

        for activity in activities:
            requests.append(Request(host, host_index, logger,  method=activity, name='unauthorized_activity/unauthorized_activity_' + activity))

        return requests

    @staticmethod
    def empty_uri(host, host_index, logger):
        return [Request(host, host_index, logger, local_uri='/ABCDEFG', name='empty_uri')]

    @staticmethod
    def malformed_method(host, host_index, logger):
        requests = []

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

        for index, method in enumerate(malformed_methods_list):
            request = Request(host, host_index, logger, name='malformed/malformed_' + str(index))
            request.method_line = method
            requests.append(request)

        return requests

    @staticmethod
    def unavailable_accept(host, host_index, logger):
        request = Request(host, host_index, logger, name='unavailable_request')
        request.add_header('Accept', 'abcd/efgh')
        return [request]

    @staticmethod
    def long_content_length(host, host_index, logger):
        request = Request(host, host_index, logger, name='long_content_length')
        request.add_header('Content-Length', str(sys.maxint))
        request.body = 'abcdefgh'
        return [request]


if __name__ == '__main__':
    request_generator = RequestGenerator()
    request_generator.create_requests()

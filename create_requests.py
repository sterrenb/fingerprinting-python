from http import Request


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
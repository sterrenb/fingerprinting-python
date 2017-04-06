# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#
import csv
from operator import itemgetter

from constants import CSV_VERBOSE, CSV
from helper import extract_banner_from_requests

csv_dict = {}


def add_request_response_to_csv(request, response, url_info):
    host = url_info.host + ':' + str(url_info.port)

    if not csv_dict.has_key(host):
        csv_dict[host] = {}

    csv_dict[host][str(request)] = response


def csv_exporter():
    f = open(CSV, 'w+')
    writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

    top = ['method']

    results = {}

    for host, requests in csv_dict.iteritems():
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

        row = [request.rstrip(), len(unique_values)]
        row.extend(unique_values)
        results_sorted.append(row)

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
# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import csv
from operator import itemgetter

from constants import CSV_VERBOSE, CSV


class Exporter:
    def __init__(self):
        self.csv_dict = {}
        self.file_handler = open(CSV, 'w+')

    def __del__(self):
        self.file_handler.close()

    def insert(self, request, response, url_info):
        host = url_info.host + ':' + str(url_info.port)

        if not self.csv_dict.has_key(host):
            self.csv_dict[host] = {}

        self.csv_dict[host][str(request)] = response

    def generate_output_file(self):
        # TODO allow intermediate
        writer = csv.writer(self.file_handler, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

        results = {}
        hosts = []

        for host, requests in self.csv_dict.iteritems():
            if CSV_VERBOSE:
                hosts.append(host)

            self.__generate_banner_reported_row(requests, results)
            results = self.__generate_requests_rows(requests, results)

        # if CSV_VERBOSE:
        #     result_rows = self.__convert_dictionary_to_list(results)
        # else:
        #     result_rows = results


        result_rows = self.__convert_dictionary_to_list(results)

        result_rows = self.add_amount_of_unique_values_to_rows(result_rows, CSV_VERBOSE)

        result_rows = sorted(result_rows, key=itemgetter(1), reverse=True)

        # result_rows = self.sort_rows_from_dictionary(results)


        self.write_top_row_to_file(writer, hosts)
        self.write_rows_to_file(result_rows, writer)

    @staticmethod
    def __convert_dictionary_to_list(dictionary):
        rows = []
        for request, responses in dictionary.iteritems():
            rows.append([request] + responses)

        return rows

    def __generate_banner_reported_row(self, requests, results):
        response_banner_key = 'BANNER_REPORTED'
        response_banner_value = self.__extract_banner_from_requests(requests)

        return self.__extend_row(results, response_banner_key, response_banner_value)

    def __generate_requests_rows(self, requests, results):
        for request, response in requests.iteritems():
            results = self.__generate_response_code_rows(request, response, results)
            # results = self.__generate_request_text_rows(request, response, results)

        return results

    def __generate_request_text_rows(self, request, response, results):
        response_text_key = request.rstrip() + ' RESPONSE_TEXT ' + response.response_code
        response_text_variable = response.response_text
        results = self.__extend_row(results, response_text_key, response_text_variable)

        return results

    def __generate_response_code_rows(self, request, response, results):
        response_code_key = request.rstrip() + ' RESPONSE_CODE'
        response_code_variable = response.response_code
        results = self.__extend_row(results, response_code_key, response_code_variable)

        return results

    @staticmethod
    def add_amount_of_unique_values_to_rows(rows, allow_duplicates):
        for index, row in enumerate(rows):
            unique_values = list(set(row[1:]))

            if allow_duplicates:
                rows[index] = [row[0]] + [len(unique_values)] + row[1:]
            else:
                rows[index] = [row[0]] + [len(unique_values)] + unique_values
        return rows

    @staticmethod
    def write_top_row_to_file(writer, hosts=[]):
        row_top = ['method']

        row_top.append('unique values')

        row_top.extend(hosts)
        writer.writerow(row_top)

    @staticmethod
    def write_rows_to_file(rows, writer):
        for row in rows:
            writer.writerow(row)

    @staticmethod
    def sort_rows_from_dictionary(dictionary):
        rows_sorted = []
        for request, responses in dictionary.iteritems():
            unique_values = list(set(responses))
            set(responses)

            row = [request.rstrip()]
            row.extend(unique_values)
            rows_sorted.append(row)
        return sorted(rows_sorted, key=itemgetter(1), reverse=True)

    @staticmethod
    def __extend_row(dictionary, key, value):
        if key not in dictionary:
            dictionary[key] = []

        dictionary[key].append(value)

        return dictionary

    @staticmethod
    def __extract_banner_from_requests(requests):
        banner = ''
        for request, response in requests.iteritems():
            if not banner:
                banner = next((header for header in response.headers if "Server" in header), '')
            else:
                break

        banner = banner.replace('Server: ', '').rstrip()

        return banner

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

    def __insert_item(self, request, response, host, attribute):
        item = Item(request, response, attribute)
        if host not in self.items:
            self.items[host] = [item]
        else:
            slf.items[host].append(item)


    def insert(self, request, response, url_info):
        host = url_info.host + ':' + str(url_info.port)

        if not self.csv_dict.has_key(host):
            self.csv_dict[host] = {}

        self.csv_dict[host][str(request)] = response


    @staticmethod
    def obtain_items_per_request(csv_dict):
        items = {}

        for host, requests in csv_dict.iteritems():
            for request, response in requests.iteritems():
                item_response_code = Item(response.response_code, 'RESPONSE_CODE')
                item_response_text = Item(response.response_text, 'RESPONSE_TEXT')

                if request not in items:
                    items[request] = {host: [item_response_code, item_response_text]}
                else:
                    if host not in items[request]:
                        items[request][host] = [item_response_code, item_response_text]
                    else:
                        items[request][host].extend([item_response_code, item_response_text])
        return items



    @staticmethod
    def obtain_items_per_host(csv_dict):
        items = {}

        for host, requests in csv_dict.iteritems():
            items[host] = {}

            for request, response in requests.iteritems():
                # response code
                # item_response_code = self.__generate_response_code_item(request, response)
                # item_response_text = self.__generate_response_text_item(request, response)

                item_response_code = Item(response.response_code, 'RESPONSE_CODE')
                item_response_text = Item(response.response_text, 'RESPONSE_TEXT')
                # self.items[host].extend([item_response_code, item_response_text])

                items[host][request] = [item_response_code, item_response_text]
        return items

    @staticmethod
    def __generate_response_code_item(request, response):
        attribute = 'RESPONSE_CODE'
        item_request = request.rstrip()
        item_response = response.response_code

        return Item(item_request, item_response, attribute)

    @staticmethod
    def __generate_response_text_item(request, response):
        attribute = 'RESPONSE_TEXT'
        item_request = request.rstrip()
        item_response = response.response_text

        return Item(item_request, item_response, attribute)



    def generate_output_file2(self):
        writer = csv.writer(self.file_handler, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

        # create dict of items per host, with attributes
        items_per_request = self.obtain_items_per_request(self.csv_dict)

        rows = []
        row_top = ['request', 'attribute', 'unique values']

        out = {}

        hosts = items_per_request.iteritems().next()[1].keys()

        row_top.extend(hosts)

        writer.writerow(row_top)

        # convert items to rows
        for request_string, hosts in items_per_request.iteritems():
            for host, items in hosts.iteritems():
                for item in items:
                    print "item for %s" % host
                    if request_string in out:
                        if item.attribute in out[request_string]:
                            out[request_string][item.attribute].append(item.output)
                    else:
                        out[request_string] = {item.attribute: [item.output]}
                    # if request_string not in out:
                    #     out[request_string] = {item.attribute: [item.output]}
                    # else:
                    #     if item.attribute not in out[request_string]:
                    #         out[request_string][item.attribute] = [item.output]
                    #     else:
                    #         out[request_string][item.attribute].append(item.output)

        for request_string, attributes in out.iteritems():
            for attribute_string, output_list in attributes.iteritems():
                unique_values = len(set(output_list))
                row = [request_string, attribute_string, unique_values] + output_list
                writer.writerow(row)

        # for host, request_items in items_per_request.iteritems():
        #     print "hi"
        #     for request_input, output_list in request_items.iteritems():
        #         for output_item in output_list:
        #             row = [request_input, output_item.attribute, output_item.output]
        #             writer.writerow(row)

        print "hi"

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

        result_rows = self.__convert_dictionary_to_list(results)
        result_rows = self.add_amount_of_unique_values_to_rows(result_rows, CSV_VERBOSE)
        result_rows = sorted(result_rows, key=itemgetter(1), reverse=True)

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

        return self.__extend_key(results, response_banner_key, response_banner_value)

    def __generate_requests_rows(self, requests, results):
        for request, response in requests.iteritems():
            results = self.__generate_response_code_rows(request, response, results)
            results = self.__generate_request_text_rows(request, response, results)

        return results

    def __generate_request_text_rows(self, request, response, results):
        response_text_key = request.rstrip() + ' RESPONSE_TEXT ' + response.response_code
        response_text_variable = response.response_text
        results = self.__extend_key(results, response_text_key, response_text_variable)

        return results

    def __generate_response_code_rows(self, request, response, results):
        response_code_key = request.rstrip() + ' RESPONSE_CODE'
        response_code_variable = response.response_code
        results = self.__extend_key(results, response_code_key, response_code_variable)

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
        row_top = ['method', 'attribute']

        row_top.append('unique responses')

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
    def __extend_key(dictionary, key, value):
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


class Item:
    def __init__(self, output, attribute):
        self.output = output
        self.attribute = attribute

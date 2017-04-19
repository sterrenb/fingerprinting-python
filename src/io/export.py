# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import csv
from operator import itemgetter

from src.static.constants import CSV


class Exporter:
    def __init__(self):
        self.csv_dict = {}
        self.request_names = {'BANNER': 'banner_grab'}
        self.file_handler = open(CSV, 'w+')

    def __del__(self):
        self.file_handler.close()

    def insert(self, request, response, url_info):
        host = url_info.host + ':' + str(url_info.port)

        self.csv_dict.setdefault(host, {})
        self.csv_dict[host].setdefault(str(request), response)

    def insert_string(self, request_string, request_name, response, url_info):
        host = url_info.host + ':' + str(url_info.port)

        self.csv_dict.setdefault(host, {})
        self.csv_dict[host].setdefault(request_string, response)

        self.request_names.setdefault(request_string, request_name)

    def obtain_items_per_request(self, csv_dict):
        items = {'BANNER': {}}

        for host, requests in csv_dict.iteritems():
            # banner name and version
            banner = Exporter.__extract_banner_from_requests(requests)
            banner_split = banner.split('/')

            if len(banner_split) > 0:
                banner_name = banner_split[0].split()[0] if len(banner_split[0]) > 0 else ''
                item_name_banner = Item(banner_name, 'NAME')
                items['BANNER'].setdefault(host, []).append(item_name_banner)

                if len(banner_split) > 1:
                    item_version_banner = Item(banner_split[1].split()[0], 'VERSION')
                    items['BANNER'].setdefault(host, []).append(item_version_banner)

            for request, response in requests.iteritems():
                # TODO split to defs
                response_items = []

                item_response_code = Item(response.response_code, 'RESPONSE_CODE')
                response_items.append(item_response_code)

                item_response_text = Item(response.response_text, 'RESPONSE_TEXT')
                response_items.append(item_response_text)

                # item_response_headers = Item(str(response.header_names()), 'HEADERS')
                # response_items.append(item_response_headers)

                items.setdefault(request, {})
                items[request].setdefault(host, []).extend(response_items)

        return items

    def generate_output_file(self):
        writer = csv.writer(self.file_handler, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

        items_per_request = self.obtain_items_per_request(self.csv_dict)

        items_per_output     = self.group_items_per_output(items_per_request)

        rows = self.make_rows(items_per_output)

        hosts = items_per_request.iteritems().next()[1].keys()
        self.write_top_row_to_file(writer, hosts)

        for row in rows:
            writer.writerow(row)

    def make_rows(self, out):
        rows = []
        for request_string, attributes in out.iteritems():
            request_name = self.request_names[request_string]
            for attribute_string, output_list in attributes.iteritems():
                unique_values = len(set(output_list))
                row = [request_name, request_string, attribute_string, unique_values] + output_list
                rows.append(row)

        rows.sort(key=lambda x: x[2], reverse=True)

        return rows

    @staticmethod
    def group_items_per_output(items_per_request):
        items_per_output = {}
        for request_string, hosts in items_per_request.iteritems():
            items_per_output.setdefault(request_string, {})
            for host, items in hosts.iteritems():
                for item in items:
                    items_per_output[request_string].setdefault(item.attribute, []).append(item.output)
        return items_per_output

    @staticmethod
    def __convert_dictionary_to_list(dictionary):
        rows = []
        for request, responses in dictionary.iteritems():
            rows.append([request] + responses)

        return rows

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
        row_top = ['name', 'method', 'attribute', 'unique responses']
        row_top.extend(hosts)
        writer.writerow(row_top)

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

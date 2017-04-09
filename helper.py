# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import pprint

# TODO deprecate
def extract_banner_from_requests(requests):
    banner = ''
    for request, response in requests.iteritems():
        if not banner:
            banner = next((header for header in response.headers if "Server" in header), '')
        else:
            break

    return banner


# def print_fingerprint(fingerprint):
#     pp = pprint.PrettyPrinter(indent=4)
#     pp.pprint(fingerprint)
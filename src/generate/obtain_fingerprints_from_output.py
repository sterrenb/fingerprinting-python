# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#
import glob
import os

from src.io.storage import store_fingerprint, write_lines
from src.static.constants import LEXICAL

output = '../../data/output'
known = '../../data/known'
f = '../../data/hosts_with_banners.txt'

hosts = []

for filepath in glob.glob(output + '/*'):
    with open(filepath, 'r') as file_handler:
        f_fingerprint = eval(file_handler.read())

        if 'SERVER_NAME_CLAIMED' in f_fingerprint[LEXICAL]:

            print filepath
            banner = f_fingerprint[LEXICAL]['SERVER_NAME_CLAIMED']

            if banner is not None:
                if not isinstance(banner, basestring):
                    banner = banner[0]
                banner_split = banner.split('/')
                if len(banner_split) > 1:
                    # store_fingerprint(known, f_fingerprint, banner.replace('/', '_'))
                    hosts.append(os.path.basename(filepath))

write_lines(f, hosts)

# get all hosts with a useful banner
# generate a spreadsheet similar to the output one with servernames instead of hostnames
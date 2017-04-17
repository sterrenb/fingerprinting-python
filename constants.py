# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import datetime

# file and directory names
CACHE = 'cache'
REQUESTS = 'requests'
BLACKLIST = 'blacklist'
# CSV = 'aaa_' + str(datetime.datetime.now()).replace(' ', '_')[:-7] + '.csv'
CSV = 'aaa.csv'

# failure handler times
PAUSE_TIME_AFTER_TIMEOUT = 1
MAX_ATTEMPTS_PER_HOST = 3

# logger formatting
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

LOGNAME_START = {
    'logname': 'setup',
    'host_index': 0,
    'host_total': 0
}

# fingerprint attribute names
LEXICAL = 'LEXICAL'
SYNTACTIC = 'SYNTACTIC'
SEMANTIC = 'SEMANTIC'

NO_RESPONSE = 'NO_RESPONSE'
NO_RESPONSE_CODE = 'NO_RESPONSE_CODE'
NO_RESPONSE_TEXT = 'NONE'

DATA_LIST = 'LIST'
DATA_NONE = None

# TODO make verbose a possibility again
# TODO make part of arguments list
CSV_VERBOSE = False
EXPORT_CSV = True
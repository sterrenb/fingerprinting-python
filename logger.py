# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import sys
import logging

from constants import BOLD_SEQ, RESET_SEQ, LOGNAME_START

FORMAT = '%(asctime)s - ' + BOLD_SEQ + '%(logname)15s' + RESET_SEQ + \
         ' [%(host_index)d/%(host_total)d] - %(levelname)7s - %(message)s'

def setup_logger(args = None):
    logging.basicConfig(stream=sys.stdout, format=FORMAT)
    logger = logging.getLogger('root')

    loglevel = args.loglevel if args is not None else logging.INFO

    logger.setLevel(loglevel)
    logger.info('starting session', extra=LOGNAME_START)

    return logger

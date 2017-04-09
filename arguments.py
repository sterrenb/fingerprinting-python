# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#

import argparse

import logging


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Fingerprint web servers and store them',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=30)
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '-i', '--input',
        help='hostname or IP address',
        dest='input'
    )
    group.add_argument(
        '-f', '--file',
        help='file with line separated hostnames or IP addresses',
        type=argparse.FileType('r'),
        dest='file'
    )

    parser.add_argument(
        '-s', '--save',
        help="directory where output fingerprints are stored",
        dest='output', default='output/'
    )

    parser.add_argument(
        '-k', '--known',
        help="directory where known fingerprints are stored",
        dest='known', default='known/'
    )

    parser.add_argument(
        '-g', '--gather',
        help="only gather data (omit comparing results)",
        action='store_true', default=False
    )

    parser.add_argument(
        '-l', '--lazy',
        help="trust server banners and omit other results if possible",
        action='store_true', default=False
    )

    parser.add_argument(
        '-v', '--verbose',
        help="show verbose statements",
        action="store_const", dest="loglevel", const=logging.INFO,
        default=logging.INFO
    )

    parser.add_argument(
        '-d', '--debug',
        help="show debugging statements",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.INFO
    )

    return parser.parse_args()

# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#
import os

from constants import BLACKLIST


class Blacklist:
    def __init__(self):
        self.file_handler = open(BLACKLIST, 'a+')

    def __del__(self):
        self.file_handler.close()

    def insert(self, host):
        self.file_handler.write(host + '\n')

    def get_hosts(self):
        self.file_handler.seek(0)
        hosts = self.file_handler.readlines()
        return map(lambda x: x.rstrip(), hosts)


import os

import pickle

# import main
from main import Response, print_fingerprint

host = '166.88.182.72'
CACHE = 'cache'

d = CACHE + '/' + host + '.' + str(80)

fs = os.listdir(d)

for f in fs:
    f_url = open(d + '/' + f, 'rb')
    response = pickle.load(f_url)

    print_fingerprint(response, host)

    f_url.close()

pass
# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#
import csv
from hotshot import stats

import copy
import matplotlib.pyplot as plt
import os
from collections import defaultdict

from src.io.storage import get_fingerprints
from src.static.constants import CSV

FILEPATH = '../../4_servers_identical_cross.csv'
KNOWN = '../../localhost_known.csv'


def get_known_servers():
    with open(KNOWN) as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        known_servers = {}

        for row in csvreader:
            if csvreader.line_num == 1:
                host_list = row[4:]
                for host in host_list:
                    known_servers.setdefault(host.split()[0], {})
            else:
                index = 0
                for known_server, known_results in known_servers.iteritems():
                    known_results[row[0] + ' - ' + row[02]] = row[index + 4]
                    index += 1
    return known_servers


def get_unknown_servers():
    with open(FILEPATH) as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

        unknown_results = {}

        for row in csvreader:
            if csvreader.line_num == 1:
                host_list = row[4:]
                for host in host_list:
                    unknown_results.setdefault(host, {})
            else:
                index = 0
                for unknown_server, unknown_result in unknown_results.iteritems():
                    try:
                        value = row[index + 4]
                    except IndexError:
                        value = "NONE"

                    try:
                        unknown_results[unknown_server][row[0] + ' - ' + row[02]] = row[index + 4]
                    except Exception:
                        unknown_results[unknown_server][row[0] + ' - ' + row[02]] = "NONE"

                    index += 1

    return unknown_results


def compare(known_servers):
    with open(FILEPATH) as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

        server_matches = {}

        x = []
        y = []

        known_server_names = {}
        for known_server in known_servers:
            known_server_names.setdefault(known_server, 0)

        for row in csvreader:
            if csvreader.line_num == 1:
                host_list = row[4:]
                for host in host_list:
                    server_matches.setdefault(host, known_server_names.copy())
            else:
                if csvreader.line_num > 3:  # to skip banner flags
                    for index, input_result in enumerate(row[4:]):
                        key = row[0] + ' - ' + row[02]
                        current_host = host_list[index]

                        for known_server_name, known_results in known_servers.iteritems():
                            if known_server_name in server_matches[current_host]:
                                if key in known_results:
                                    known_result = known_results[key]
                                    if input_result == known_result:
                                        # print "%s matched, incrementing" % key
                                        server_matches[current_host][known_server_name] += 1

            # TODO count max occurences per unknown server
            # count = 0
            # for i in z:
            #     if i is max(z):
            #         count += 1

            number_of_servers_with_one_possibility = 0

            for host, unknown_matches in server_matches.iteritems():
                number_of_possibilities = 0
                most_matches = max(unknown_matches.values())

                for server_name, matches in unknown_matches.iteritems():
                    if matches == most_matches:
                        number_of_possibilities += 1
                    pass

                # increase number of servers with one possibility
                if number_of_possibilities == 1:
                    number_of_servers_with_one_possibility += 1

            x.append(csvreader.line_num)
            y.append(number_of_servers_with_one_possibility)

        plt.plot(x, y)
        plt.xlabel('number of requests parsed')
        plt.ylabel('number_of_servers_with_one_possibility')
        plt.show()

        print "hi"


def score_server(unknown_server, unknown_output, ground_truth):
    # goal: dict{known, score}

    scores = {}

    for known_server, known_output in ground_truth.iteritems():
        score = 0

        # TODO variable to determine how many request/response pairs are used for scoring
        for known_request, known_response in known_output.iteritems():
            if known_request in unknown_output and unknown_output[known_request] == known_response:
                score += 1

        scores.setdefault(known_server, score)

    return scores


def determine_scores(ground_truth, unknown_servers):
    scores = {}

    for unknown_server, unknown_output in unknown_servers.iteritems():
        score = score_server(unknown_server, unknown_output, ground_truth)
        scores.setdefault(unknown_server, score)

    return scores

# get all the possibilities per score, i.e. a list of the possibilities with max score
def get_possibilities(scores):
    possibilities = copy.deepcopy(scores)
    for unknown_server, score_dict in scores.iteritems():
        max_score = score_dict[max(score_dict.iterkeys(), key=(lambda key: score_dict[key]))]

        for known_server, known_score in score_dict.iteritems():
            if known_score < max_score:
                possibilities[unknown_server].pop(known_server, None)

    return possibilities


# show a histogram with buckets per number of possibilities
def visualise_possibilities(possibilities):
    possibilities_per_num = {}

    poss = []

    for unknown_servers, possible_servers in possibilities.iteritems():
        pass

        num = len(possible_servers)

        poss.append(num)

        if num in possibilities_per_num:
            possibilities_per_num[num] += 1
        else:
            possibilities_per_num[num] = 1

        # num = possible_servers.iteritems().next()[-1]

        # if num in possibilities_per_num:
        #     possibilities_per_num[num] = possibilities_per_num[num] + len(possible_servers)
        # else:
        #     possibilities_per_num[num] = len(possible_servers)


    num_list = possibilities_per_num.items()
    # num_of_possibilities, occurrences = zip(*num_list)

    # the histogram of the data8
    n, bins, patches = plt.hist(poss, 10, normed=0, facecolor='green', alpha=0.75)

    plt.xlabel('possible server matches')
    plt.ylabel('unknown servers')

    plt.show()

    pass


if __name__ == '__main__':
    known_servers = get_known_servers()
    unknown_servers = get_unknown_servers()
    scores = determine_scores(known_servers, unknown_servers)
    possibilities = get_possibilities(scores)
    visualise_possibilities(possibilities)
    # compare(known_servers)



    # load in server print csv
    # load in unknown csv
    # per row, compare the output of an unknown with all server prints
    # if no match, remove the serverprint from the set

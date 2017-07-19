# Copyright 2017 Thomas Sterrenburg
#
# Licensed under the MIT License (the License); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at https://opensource.org/licenses/MIT#
import csv
import copy

FILEPATH = '../../1662_servers_parsed.csv'
REQUEST_LIMIT = 200


def split_dict(d):
    half = len(d) / 2
    return dict(d.items()[half:]), dict(d.items()[:half])


def get_requests_ordered():
    with open(FILEPATH) as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

        requests_ordered = []

        for row in csvreader:
            if csvreader.line_num > 1:
                if row[0] != "":
                    tup = (row[0] + ' - ' + row[02], row[3])
                    requests_ordered.append(tup)

    return requests_ordered


def get_servers():
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


def determine_scores(ground_truth, test_set, requests_ordered, limit):
    scores = {}

    requests_top, requests_unique = zip(*requests_ordered)

    if limit > 0:
        requests_top = requests_top[:limit]


    index = 0
    for unknown_server, unknown_output in test_set.iteritems():
        score = score_server(unknown_server, unknown_output, ground_truth, requests_top, limit)
        scores.setdefault(unknown_server, score)

        if(index % 100 == 0):
            print "determining score for %s" % unknown_server

        index += 1

    return scores


def score_server(unknown_server, unknown_output, ground_truth, requests_top, limit):
    # goal: dict{known, score}


    scores = {}

    for known_server, known_output in ground_truth.iteritems():
        score = 0

        # limit known_output to the top x requests for comparison
        known_output_filtered = {}
        for request_top in requests_top:
            known_output_filtered[request_top] = known_output[request_top]

        # TODO variable to determine how many request/response pairs are used for scoring
        for known_request, known_response in known_output_filtered.iteritems():
            if known_request in unknown_output and unknown_output[known_request] == known_response:
                score += 1

        # TODO maybe setdefault is wrong if multiple of the same server type are in ground truth: doesn't override if present already?
        scores.setdefault(known_output['banner_grab - VERSION'], score)

    return scores


def get_possibilities(scores):
    possibilities = copy.deepcopy(scores)
    for unknown_server, score_dict in scores.iteritems():
        max_score = score_dict[max(score_dict.iterkeys(), key=(lambda key: score_dict[key]))]

        for known_server, known_score in score_dict.iteritems():
            if known_score < max_score:
                possibilities[unknown_server].pop(known_server, None)

    return possibilities


def get_number_of_requests(d):
    n = d.iteritems().next()
    return len(n[1])


def determine_correct_matches(possibilities, test_set):
    correct_matches = {}

    for unknown_server, possibility in possibilities.iteritems():
        match = False

        # TODO check for banner_name as well (i.e. substring of some element of possibility
        banner_name_expected = test_set[unknown_server]['banner_grab - NAME']
        if banner_name_expected in possibility.iteritems().next()[0]:
            match = True

        correct_matches.setdefault(unknown_server, match)
    return correct_matches


def determine_accuracy(correct_matches):
    trues = 0

    match_list = correct_matches.values()

    for match in match_list:
        if match:
            trues += 1

    return float(trues) / len(match_list)


def measure_accuracy(ground_truth, test_set, requests_ordered):
    # obtain scores based on matching replies
    scores = determine_scores(ground_truth, test_set, requests_ordered, REQUEST_LIMIT)

    # get the number of requests used
    # if REQUEST_LIMIT == 0:
    #     number_of_requests = get_number_of_requests(ground_truth)
    # else:
    #     number_of_requests = REQUEST_LIMIT

    # filter the scores to only contain the top score(s)
    possibilities = get_possibilities(scores)

    # determine correct matches based on comparing the determined banner and reported banner
    correct_matches = determine_correct_matches(possibilities, test_set)

    accuracy = determine_accuracy(correct_matches)

    print "accuracy: %f" % accuracy

if __name__ == '__main__':
    # TODO possibly wrap in function and make smaller partitions for better accuracy measurement


    # store ground truth and test set
    servers = get_servers()
    left, right = split_dict(servers)

    # obtain requests used, ordered by number of unique replies
    requests_ordered = get_requests_ordered()

    # LEFT
    measure_accuracy(left, right, requests_ordered)
    measure_accuracy(right, left, requests_ordered)

    pass

    # # ROADMAP
    #
    # correct = 0
    # total = 0
    #
    # # obtain servers from disk
    # servers = get_servers()
    #
    # # split in 2 for cross validation
    # ground_truth = get_first_half(servers)
    # test = get_last_half(servers)
    #
    #
    # # loop over all test servers
    # for unknown_server in test:
    #     # determine a score based on the ground_truth set
    #
    #     # store the reported banner to compare with later on
    #     expected_score = get_banner(unknown_server)
    #
    #     # determine the best scoring match for this server based on the ground_truth
    #     determined_best_score = determine_server(unknown_server, ground_truth)
    #
    #     # compare the determined and expected score
    #     if determined_best_score == expected_score:
    #         correct += 1
    #
    #     total += 1
    #
    # # determine accuracy
    # accuracy = correct / total

# -*- coding: utf-8 -*-
"""  CNT5410 -- Assignment 1: Passwords -- rainbow.py
"""

import sys
import utils

"""
## Build rainbow table.

    Inputs:
        pc: performance counter (PerfCounter),
        next_fn: next candidate password function,
        out_fp: output filepath,
        num_chains: number of chains to compute,
        k: length of each chain,
        pwhash_fn: compute password hash function,
        reduce_fn: reduce function family,
        random_candidates_fn: random password candidates function

    Outputs:
        None
"""
def build_rainbow(pc, out_fp, num_chains, k, pwhash_fn, reduce_fn, random_candidates_fn):

    table = {}

    ## TODO: Problem 3.4 (5 pts) ##
    ## Put your code here to avoid duplicating start points

    startpoints={}

    sys.stdout.write('Building rainbow table')
    for i in range(0, num_chains):
        # build chain i
        startpoint = random_candidates_fn()

        ## TODO: Problem 3.4 (5 pts) ##
        ## Put your code here to avoid duplicating start points
        if i > 36**4:
            break

        while (startpoint in startpoints):
            startpoint=random_candidates_fn()
        startpoints[startpoint]=True

        current = startpoint

        for j in range(0, k):
            # do one iteration
            hv = pwhash_fn(current)
            next = reduce_fn(j, hv)
            current = next

        pc.inc(k) # increment by k

        if i > 0 and (pc.get() % 100000) < k:
            sys.stdout.write('.')
            sys.stdout.flush()

        endpoint = current

        if endpoint not in table:
            table[endpoint] = []
        table[endpoint].append({'chain': i, 'start': startpoint, 'end': endpoint})

    utils.write_json(out_fp, table)
    print(' done.')


## TODO: Problem 2.1 --- (20 pts) ##
"""
## Rainbow table lookup.

    Inputs:
        pc: performance counter (PerfCounter),
        in_fp: table filepath,
        k: length of each chain,
        pwhash_fn: compute password hash function,
        reduce_fn: reduce function family,
        pwhash_list: the list of password hashes we want to invert (find the plaintext password for)
        
    Outputs:
        results: array of length len(pwhash_list) containing the matching passwords (or None)
"""
def lookup_rainbow(pc, in_fp, k, pwhash_fn, reduce_fn, pwhash_list, verbose = False):

    table = utils.read_json(in_fp)

    pwres = [None for i in range(len(pwhash_list))]
    for pwidx, pwhash in enumerate(pwhash_list):
        found = False

        chain_infos = []
        ## TODO ##
        ## Put your code here
        for i in range(k):
            next_hash=pwhash
            for l in range(i,k):
                next_reduce=reduce_fn(l,next_hash)
                next_hash=pwhash_fn(next_reduce)
                if next_reduce in table:
                    chain_infos.extend(table[next_reduce])
        verbose = False
        # raise NotImplementedError()

        pc.inc(k)  # increment by k

        for j, chain_info in enumerate(chain_infos):
            chain_idx = chain_info['chain']
            startpoint = chain_info['start']
            current = startpoint

            if pwres[pwidx] is not None:
                break

            found = False
            ## TODO ##
            ## Put your code here
            for j in range(0,k):
                hv=pwhash_fn(current)
                next=reduce_fn(j,hv)
                if hv==pwhash:
                    found=True
                    pwres[pwidx]=current
                    break
                current=next
            else:
                verbose=True

            if verbose and not found:
                print('\t[False alarm] for pwhash {} in chain {} [start: {}, end: {}]!'.format(pwhash, chain_idx, startpoint, chain_info['end']))

    return pwres

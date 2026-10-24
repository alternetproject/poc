# this module is experimental attempt to understand Tor-style proof-of-work
#
# Tor proof-of-work is an example of CPP:
#  * https://en.wikipedia.org/wiki/Client_Puzzle_Protocol
# see:
#  * https://onionservices.torproject.org/technology/security/pow/
#  * https://anubizhost.com/fa/tor-hidden-service-proof-of-work
#  * https://spec.torproject.org/hspow-spec/
#
# that last doc links to 3 related IETF works:
#  * https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-ddos-protection-10
#  * https://www.ietf.org/archive/id/draft-nir-tls-puzzles-00.txt
#  * https://www.ietf.org/archive/id/draft-nygren-tls-client-puzzles-02.txt
#
# perl implementations of nginx proxy middleware requiring PoW & Plack PSGI server
#  * https://github.com/pstadt/nginx-perl-pow
#  * https://metacpan.org/dist/Plack-Middleware-ProofOfWork
#
# this module originally based on a couple of found toy implementations:
#  * https://github.com/mvarge/proof_of_work
#  * https://github.com/bstnbuck/Proof-of-Work/blob/master/python/pow.py
# though I think there are more lessons to ba had from the Plack implementation:
#  * https://metacpan.org/release/PSTADT/Plack-Middleware-ProofOfWork-0.24/source/lib/Plack/Middleware/ProofOfWork.pm

import argparse
import datetime
import hashlib
import random
import secrets
import sys
import time


GIVEUP_COUNT = 1000000


# From the Plack docs: "The middleware uses SHA-256 hashing and requires
# clients to find a nonce that results in a hash with a specified number of
# leading zeros."
#
# Plack concats a predictable input string: $user_agent|$timestamp|$accept_language|$host
# & asks client, find me an integer nonce that will result in a hash with *n* leading zeros
# the number of leading zeros corresponding to level/difficulty
# to verify the request, server only has to hashlib.sha256(f"{input_string}:{nonce}")


def _gen_hash(input_string, nonce, verbose=False):
    h = hashlib.sha256(f'{input_string}:{nonce}'.encode('utf-8')).hexdigest()
    if verbose:
        print(f'{nonce:>8} {h}', file=sys.stderr)
    return h


def find_nonce(input_string, level=1, verbose=False):
    if verbose:
        print(f'lvl {level:>2} str {input_string}', file=sys.stderr)
    if not isinstance(level, int) or not level >= 0:
        raise ValueError(f'level must be int >= 0')

    count = 0
    search = '0' * level
    while True:
        nonce = random.randint(10, 9999999)
        h = _gen_hash(input_string, nonce, verbose)
        if h.startswith(search):
            return nonce

        if count == GIVEUP_COUNT:
            raise RuntimeError(f'GIVEUP_COUNT hash not found for {input_string}')

        count += 1


def test_nonce(nonce, input_string, level=1, verbose=False):
    if verbose:
        print(f'lvl {level:>2} nonce {nonce:>8} str {input_string}', file=sys.stderr)
    search = '0' * level
    h = _gen_hash(input_string, nonce, verbose)
    return h.startswith(search)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_string', help='input string')
    parser.add_argument('-l', '--levels', type=int, default=5, help='demo how many levels?')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()


def demo():
    args = parse_args()
    print(f'\ndemo PoW for string: {args.input_string}\n')
    for level in range(args.levels):
        start = time.time()
        nonce = find_nonce(args.input_string, level, args.verbose)
        valid = test_nonce(nonce, args.input_string, level, args.verbose)
        end = time.time()
        elapsed = datetime.timedelta(end - start)
        print(f'level={level} nonce found: {nonce}, valid={valid}')
        print(f'elapsed time: {elapsed}\n')
    # return success
    return(0)


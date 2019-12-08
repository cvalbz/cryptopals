import sys
import web
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray
import hashed_mac
import time
import threading
import requests
from collections import Counter
from break_hmac_sha1_artificial_timing_leak import sign, verify, default_timing, time_signature, test_signature, MyWebserver
from operator import itemgetter

ARTIFICIAL_TIMING = 0.005
KEY = crypto_random_bytes(64)


def break_byte(signature_to_break, so_far, nr_traces=25):
    overhead = default_timing()

    results = []
    for byte_candidate in range(256):
        signature_to_break[so_far] = byte_candidate

        exps = []
        for i in range(nr_traces):
            t = time_signature(signature_to_break)
            exps.append(t)

        results.append( (byte_candidate, sum(exps) / len(exps)) )

    return max(results, key=itemgetter(1))[0]

def break_byte_statistic(signature_to_break, so_far, nr_exp=1):
    bytes_found = [break_byte(signature_to_break, so_far) for i in range(nr_exp)]
    return Counter(bytes_found).most_common(1)[0][0]

def break_hmac():
    overhead = default_timing()

    signature_to_break = bytearray([0] * 20)
    so_far = 0

    last_timing = overhead
    for i in range(20):
        byte_found = break_byte_statistic(signature_to_break, so_far)
        signature_to_break[so_far] = byte_found
        so_far += 1

    return signature_to_break

def main():
    server = MyWebserver()
    server.start()
    time.sleep(3)

    found_sig = break_hmac()

    url = f"http://0.0.0.0:8080/test?file=25.txt&signature={bytearray2hexstring(found_sig)}"
    r = requests.get(url)
    if b"True" in r.content:
        print("challenge 4.32 completed.")
    else:
        print("challenge 4.32 failed.")

if __name__ == "__main__":
    main()
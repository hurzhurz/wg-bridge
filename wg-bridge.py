import binascii
import socket
import base64
import hashlib
import time
import argparse


TIMEOUT_INIT = 10
TIMEOUT_ESTABLISHED = 60


# define gloables variables

key_groups = []
"""
list for storage for public key lists and associated peers as possible tager addresses, each element is a dict:
{
  keys: [pubkey1, pubkey2],
  peers: [peerid1, peerid2, peerid3]
}
"""

mac1keys = {}
"""
dict for storage of pre generated mac1keys
  pubkey: mac1key
"""

peers = {}
"""
dict for storage of peers
peerid: {
  addr: (ip, port) / None if timed out
  peer: peerid if established / None if in init phase
  last: monotonic time of last received packet
}
"""


def parseargs():
    parser = argparse.ArgumentParser(description='Wireguard Bridge')
    parser.add_argument("--port", "-p", type=int, default=51820, help="Listen port (default 51820)")
    parser.add_argument("--keys", "-k", type=str, action='append', required=True, help="Comma-separated list of public keys that should be able to communicate with each other. Multiple lists are possible and lists can overlap / have same keys.")
    return parser.parse_args()


def try_sock_sendto(data, address):
    try:
        sock.sendto(data, address)
    except Exception as e:
        print("Exception on sendto", address, e)


def gen_mac1key(key):
    key = base64.b64decode(key)
    label = "mac1----".encode('ascii')
    h = hashlib.blake2s()
    h.update(label)
    h.update(key)
    return h.digest()


def verify_mac1(data, mac1key):
    offset = 116 if data[0] == 1 else 60
    msg = data[0:offset]
    msg = bytes(data[0:1]) + b'\x00\x00\x00' + bytes(msg[4:])
    mac1 = data[offset:offset+16]
    h = hashlib.blake2s(key=mac1key, digest_size=16)
    h.update(msg)
    return (mac1 == h.digest())


def find_key(data):
    for key, mac1key in mac1keys.items():
        if verify_mac1(data, mac1key):
            return key
    return None


def handle_init(data, address):
    global peers
    global key_groups
    sender = data[4:8]
    # ignore if peerid already in use
    if sender in peers and peers[sender]['peer'] is not None:
        return
    # check if destination public key is known
    key = find_key(data)
    if not key:
        return
    # store sender in peer list
    peers[sender] = {'addr': address, 'peer': None, 'last': time.monotonic()}
    possible_peers = []
    # search all keygroups with public key and store sender peerid as reference and create list of other peers as forwarding tagets
    for kg in key_groups:
        if key in kg['keys']:
            possible_peers.extend(kg['peers'])
            kg['peers'].append(sender)
    targets = set([peers[peer]['addr'] for peer in set(possible_peers)])-set([address])
    print("initiaton received", "from address", address, "sender-index:", binascii.hexlify(sender), "public-key:", key, "forwarding-to:", list(targets))
    # forward init packet
    for target in targets:
        try_sock_sendto(data, target)


def handle_initresponse(data, address):
    global peers
    sender = data[4:8]
    receiver = data[8:12]
    # ignore packet if receiver unknown or if sender or receiver already belong to established connection
    if (sender in peers and peers[sender]['peer'] is not None) or receiver not in peers or peers[receiver]['peer'] is not None:
        return
    # check if destination public key is known
    key = find_key(data)
    if not key:
        return
    # search/verify if public key and receiver peerid belong together
    for kg in key_groups:
        if key in kg['keys'] and receiver in kg['peers']:
            print("initiaton response / session established:", "from address", address, "sender-index:", binascii.hexlify(sender), "receiver-index:", binascii.hexlify(receiver), "public-key:", key)
            # add sender to peer list and croos-reference sender/receiver to mark them as established connection
            peers[sender] = {'addr': address, 'peer': receiver, 'last': time.monotonic()}
            peers[receiver]['peer'] = sender
            # forward init response packet
            try_sock_sendto(data, peers[receiver]['addr'])
            return


def handle_cookiereply(data, address):
    # cookiereply if receiver is known and in init state
    receiver = data[4:8]
    if receiver in peers and peers[receiver]['peer'] is None:
        print("forward initiation cookie reply from", address, "for", receiver)
        try_sock_sendto(data, peers[receiver]['addr'])


def handle_transport(data, address):
    global peers
    receiver = data[4:8]
    # check if receiver exists and is in etsablished state
    if receiver not in peers or peers[receiver]['peer'] is None:
        return
    # read sender id from crossreference and update address and last-packet-time
    sender = peers[receiver]['peer']
    peers[sender]['addr'] = address
    peers[sender]['last'] = time.monotonic()
    # if receiver is not timed out, forward packet
    if peers[receiver]['addr'] is not None:
        try_sock_sendto(data, peers[receiver]['addr'])


last_handle_timeout = time.monotonic()


def handle_timeout():
    global last_handle_timeout
    global peers
    now = time.monotonic()
    if (now - last_handle_timeout) < 1.0:
        return
    last_handle_timeout = now
    for id in list(peers):
        if id not in peers:
            continue
        # time out peers in init state
        if peers[id]['peer'] is None:
            if (now - peers[id]['last']) > TIMEOUT_INIT:
                del peers[id]
                print("timeout initiation peer", binascii.hexlify(id))
        # remove if broken crossreference
        elif peers[id]['peer'] not in peers:
            del peers[id]
        # time out peers in established state
        elif (now - peers[id]['last']) > TIMEOUT_ESTABLISHED:
            # check if peer already timed out too and remove both
            if peers[peers[id]['peer']]['addr'] is None:
                print("timeout / remove established peers:", binascii.hexlify(id), binascii.hexlify(peers[id]['peer']))
                del peers[peers[id]['peer']]
                del peers[id]
            # mark as timed out by setting address to None
            elif peers[id]['addr'] is not None:
                print("timeout established peer:", binascii.hexlify(id))
                peers[id]['addr'] = None
    # cleanup of no more existing peers stored in key groups
    for kg in key_groups:
        kg['peers'] = [peer for peer in kg['peers'] if peer in peers and peers[peer]['addr']]


# read cli arguments
args = parseargs()

# fill key_groups dict-list with pubkeys from cli arguments
for keys in args.keys:
    key_groups.append({'keys': list(map(str.strip, keys.split(','))), 'peers': []})

# pregenerate mac1 key for each pubkey
for key in set([key for kg in key_groups for key in kg['keys']]):
    mac1keys[key] = gen_mac1key(key)

# open listen socket
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind(('', args.port))
sock.settimeout(1)

while True:
    handle_timeout()
    try:
        data, address = sock.recvfrom(10000)
    except socket.error:
        pass
    else:
        if len(data) == 0:
            continue
        if data[0] == 4 and len(data) >= 32:  # data or keepalive
            handle_transport(data, address)
        elif data[0] == 1 and len(data) == 148:  # handshake initiation
            handle_init(data, address)
        elif data[0] == 2 and len(data) == 92:  # handshake initiation response
            handle_initresponse(data, address)
        elif data[0] == 3 and len(data) == 64:  # handshake initiation cookie reply
            handle_cookiereply(data, address)

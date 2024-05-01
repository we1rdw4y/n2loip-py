import sys
import itertools
import hashlib
import string
from argparse import ArgumentParser
from ipaddress import ip_network

def net_dbg(net):
    NET_ATTRS = [
        # 'packed',
        'max_prefixlen',
        'network_address',
        'hostmask',
        'netmask',
        'with_prefixlen',
        'compressed',
        'exploded',
        'with_netmask',
        'with_hostmask',
        'num_addresses',
        'prefixlen',
    ]
    print(net)
    for attr in NET_ATTRS:
            v = getattr(net, attr, None)
            if not v:
                continue
            print("\t", attr, "=", v)

log_level = 0

def log_init(ll: int):
    global log_level
    log_level = ll

def log(ll: int, *nargs, **kwargs):
    if ll > log_level:
        return
    print(*nargs, **kwargs, file=sys.stderr)

def log_error(*nargs, **kwargs):
    log(0, *nargs, **kwargs)

def log_info(*nargs, **kwargs):
    log(1, *nargs, **kwargs)

def log_debug(*nargs, **kwargs):
    log(2, *nargs, **kwargs)

TRANSLATION = {
    'a': ["4"],
    'b': ["13"],
    'e': ["3"],
    'g': ["6", "9"],
    'h': ["4"],
    'i': ["1"],
    'j': ["d"],
    'k': ["15"],
    'l': ["1", "2"],
    'm': ["177"],
    'n': ["17"],
    'o': ["0"],
    'p': ["3.14"],
    'q': ["9", "15"],
    'r': ["12"],
    's': ["5"],
    't': ["7"],
    'u': ["4"],
    'v': ["4"],
    'w': ["44"],
    'x': ["155"],
    'y': ["e", "ee", "3", "33"],
    'z': ["743"],
}

ap = ArgumentParser()
ap.add_argument('service')
# ap.add_argument('-6', dest='ip_version', type=int)
ap.add_argument('-v', '--verbose', action='count', default=0)

LO_NET = ip_network("127.0.0.0/8")
# net_dbg(LO_NET)
CHR_LEN_MAX = (LO_NET.max_prefixlen - LO_NET.prefixlen) // 8 * 2
HASHES = [
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512",
]

def main(service="", verbose=0):
    log_init(verbose)
    service = service.lower()
    if len(service) > CHR_LEN_MAX:
        log_info("maximum chars possible:", CHR_LEN_MAX)
        log_info("got:", len(service))
    ret = []
    for ch in service:
        ch_variants = []
        if ch in string.hexdigits:
            ch_variants.append(ch)
        if ch in TRANSLATION:
            ch_variants.extend(TRANSLATION[ch])
        ret.append(ch_variants)
    log_debug("Spelling choices:")
    rows = max(map(len, ret), default=0)
    for row in range(rows):
        for ch_variants in ret:
            width = max(map(len, ch_variants), default=0)
            ch = ""
            if row < len(ch_variants):
                ch = ch_variants[row]
            log_debug(ch.rjust(width), end=" ")
        log_debug()
    log_debug("Variants:")
    addr_iter = itertools.product(*ret)
    while addr := next(addr_iter, None):
        addr_str = "".join(addr)
        if len(addr_str) % 2 == 1:
            addr_iter = itertools.chain([("0", *addr), (*addr, "0")], addr_iter)
            continue
        log_info("Hex string:", addr_str)
        addr = (127).to_bytes() + bytes.fromhex(addr_str[:CHR_LEN_MAX])
        print(".".join(map(str, addr)))

    log_debug("Fallback: hashes")
    for hashfn in HASHES:
        hash = getattr(hashlib, hashfn)(service.encode()).digest()
        log_info("Hash", f"{hashfn}: {hash.hex()}")
        hash = (127).to_bytes() + hash[:CHR_LEN_MAX // 2]
        print(".".join(map(str, hash)))

if __name__ == "__main__":
    argv = ap.parse_args()
    main(**vars(argv))

from collections import deque
import binascii
import os
from hashlib import blake2b
import hashlib
from Crypto import Random
import copy
from strgen import StringGenerator


def to(text):
    return hex(int(binascii.hexlify(text.encode()).decode(), 16))[2:]


def fromh(hex1):
    return binascii.unhexlify(hex(int(hex1, 16))[2:].encode()).decode()


def rkeys(key):
    keys = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', key.encode(), b'6942069', iterations=10, dklen=320)).decode()
    lkeys = []
    b = ''
    allkeys = []
    key = []
    row = []

    for x in keys:
        b += x
        if len(b) == 2:
            lkeys.append(b)
            b = ''
    for a in lkeys:
        row.append(a)
        if len(row) == 4:
            key.append(row.copy())
            row.clear()
        if len(key) == 4:
            allkeys.append(key.copy())
            key.clear()
    return allkeys


def mix(b, key):
    eblocks = []
    cipher = []
    index = 0
    row = 0
    for a in range(0, 16):
        m = hex((int(key[row][0], 16) + int(b[row][index], 16)) % 0x100)[2:].zfill(2)
        m = hex((((int(m, 16) ^ int(key[index][1], 16)) ^ int(key[index][2], 16)) ^ int(key[index][3], 16)) ^ int(
            key[index][index], 16))[2:].zfill(2)
        cipher.append(m)
        if len(cipher) == 4:
            eblocks.append(cipher.copy())
            cipher.clear()
        if index == 3:
            row += 1
            index = 0
        else:
            index += 1
    return eblocks


def unmix(e, key):
    dblocks = []
    text = []
    index = 0
    row = 0
    for a in range(0, 16):
        m = hex((((int(e[row][index], 16) ^ int(key[index][index], 16)) ^ int(key[index][3], 16)) ^ int(key[index][2],
                                                  16)) ^ int(key[index][1], 16))[2:].zfill(2)
        m = hex((int(int(m, 16) - int(key[row][0], 16))) % 0x100)[2:].zfill(2)
        text.append(m)
        if len(text) == 4:
            dblocks.append(text.copy())
            text.clear()
        if index == 3:
            row += 1
            index = 0
        else:
            index += 1
    return dblocks


def blockify(l, use_iv=True):
    if use_iv:
        iv = binascii.hexlify(Random.get_random_bytes(15)).decode()  # iv
        l = iv + l
        p = 0
        while (len(l) + 2 + p) % 32 != 0:
            p += 1
        pl = hex(p)[2:].zfill(2)
        l = pl + l
    blocks = []
    b = []
    block = []
    counter = 2
    by = []
    n = ''

    if len(l) % 32 != 0:
        while len(l) % 32 != 0:
            l += binascii.hexlify(os.urandom(1)).decode()
    for a in l:
        n += a
        if len(n) == 2:
            by.append(n)
            n = ''
    for x in by:
        b.append(x)
        if len(b) == 4:
            block.append(b.copy())
            b.clear()
        if len(block) == 4:
            blocks.append(block.copy())
            block.clear()
        counter += 2
    return blocks


def unblockify(blocks):
    t = ''
    for bs in blocks:
        for b in bs:
            for r in b:
                t += r
    return t


def dec_blocks(b):
    pl = b[0][0][0]
    b = unblockify(b[1:])
    return b[:-int(pl, 16)]


def xor(k, b):
    # print('block to be XORED: ', b)
    for key, (bindex, block) in zip(k, enumerate(b)):
        for kb, (bi, bb) in zip(key, enumerate(block)):
            d = hex(int(kb, 16) ^ int(bb, 16))[2:].zfill(2)
            # print(kb, ' ^ ', bb, ' = ', d)
            b[bindex][bi] = d
    return b


def round(rk, b):
    e = []
    for block in b:
        et = xor(rk, block)
        et = mix(et, rk)
        e.append(et)
    return e


def unround(rk, b):
    d = []
    e = ''
    for block in b:
        e = unmix(block, rk)
        e = xor(rk, e)
        d.append(e)
    return d


def enc(key, pt):
    keys = rkeys(key)
    ptb = blockify(to(pt), use_iv=True)
    for k in keys:
        ptb = round(k, ptb)
    return unblockify(ptb)


def dec(key, ct):
    keys = rkeys(key)
    keys.reverse()
    ctb = blockify(ct, use_iv=False)
    for k in keys:
        ctb = unround(k, ctb)
    return fromh(dec_blocks(ctb))


def test(rounds=1):
    e = []
    d = []
    for _ in range(rounds):
        otk = binascii.hexlify(os.urandom(80)).decode()
        t = StringGenerator('[\d\w]{100}').render()
        print(t)
        ec = enc(otk, t)
        e.append(t)
        dc = dec(otk, ec)
        d.append(dc)
    for a, b in zip(e, d):
        if a != b:
            print(e.index(a))
            print('encrypted: %s\n' % a)
            print('decrypted: %s\n' % b)
            return False
    return True


with open('1.f', 'rb') as f:
    w = binascii.hexlify(f.read()).decode()
print('file read: ', w)
print(w, '\n')
e = enc('secret', w)
print('cipher text: %s\n' % e)
d = dec('secret', e)
print('decrypted text: %s' % d)
# test(100)

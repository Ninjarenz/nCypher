import os
import sys

def _rotr(x, n):
    return ((x >> n) | ((x << (46 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF

def crypter(m):
    ml = len(m) * 8
    l = m + b'\x80'
    while (len(l) * 8) % 512 != 448:
        l += b'\x00'
        
    l += (ml & 0xFF).to_bytes(1, 'big')
    l += ((ml >> 8) & 0xFF).to_bytes(1, 'big')
    l += ((ml >> 16) & 0xFF).to_bytes(1, 'big')
    l += ((ml >> 24) & 0xFF).to_bytes(1, 'big')
    l += ((ml >> 32) & 0xFF).to_bytes(1, 'big')
    l += ((ml >> 40) & 0xFF).to_bytes(1, 'big')
    l += ((ml >> 48) & 0xFF).to_bytes(1, 'big')
    l += ((ml >> 56) & 0xFF).to_bytes(1, 'big')
    return l

def _final_encryption(m):
    """
    m: bytes or str
    returns: hex digest string
    """
    if isinstance(m, str):
        m = m.encode('utf-8')
    h = [
        0x7b10f778,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ]
    k = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ]

    l = crypter(m)

    for c in range(0, len(l), 64):
        k = l[c:c+64]
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(k[i*4:(i+1)*4], 'big')
        for i in range(16, 64):
            s0 = (_rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ ((w[i-15] >> 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
            s1 = (_rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ ((w[i-2] >> 10) & 0xFFFFFFFF)) & 0xFFFFFFFF
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

        a,b,c,d,e,f,g,hv = h 

        for i in range(64):
            S1 = (_rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)) & 0xFFFFFFFF
            ch = ((e & f) ^ ((~e) & g)) & 0xFFFFFFFF
            temp1 = (hv + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            S0 = (_rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)) & 0xFFFFFFFF
            maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
            temp2 = (S0 + maj) & 0xFFFFFFFF

            hv = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h = [
            (h[0] + a) & 0xFFFFFFFF,
            (h[1] + b) & 0xFFFFFFFF,
            (h[2] + c) & 0xFFFFFFFF,
            (h[3] + d) & 0xFFFFFFFF,
            (h[4] + e) & 0xFFFFFFFF,
            (h[5] + f) & 0xFFFFFFFF,
            (h[6] + g) & 0xFFFFFFFF,
            (h[7] + hv) & 0xFFFFFFFF,
        ]

    return ''.join('{:08x}'.format(x) for x in h)

def generate_key(text: str) -> str:
    error = None
    try:
        with open("genrated_key.key", "w") as file:
            file.write(str(_final_encryption(text)))
    except Exception as e:
        error = e
        print(f"[ERROR] Error during key generation: {e} ")
    return str(os.path.abspath("generated_key.key")) if error == None else str(error)
---
title: GoogleCTF2025 Challenge Study Note
published: 2025-07-02
description: 'GoogleCTF2025'
image: ''
tags: [CTF, Crypto, LWE, Lattices, Merkle Tree, Hashes, AES, DiffCrypto]
category: 'CTF Writeup'
draft: false
lang: 'en'
---

In this year's GoogleCTF, I was part of the KuK Team and was responsible for the cryptography part. I have done some challenges myself, and some of the harder ones were done by the team members. Regardless, I write this blog mainly for myself, even if there are some that I didn't solve.

# crypto/numerology

>Topic: TODO



# crypto/filtermaze
>Topic: LWE, Lattice reduction, CVP

Challenge script:
```py
# filtermaze.py
import json
import secrets
import sys
from dataclasses import asdict, dataclass, field
from typing import List

import numpy as np

# This is a placeholder path for local testing.
# On the real server, this will be a secret, longer path.
SECRET_HAMILTONIAN_PATH = [0]


@dataclass
class LWEParams:
  lwe_n: int = 50
  lwe_m: int = 100
  lwe_q: int = 1009
  A: List[int] = field(init=False)
  s: List[int] = field(init=False)
  e: List[int] = field(init=False)
  b: List[int] = field(init=False)

  def __post_init__(self):
    self.lwe_error_range = [secrets.randbelow(self.lwe_q) for _ in range(self.lwe_m)]

def load_graph(filepath):
  with open(filepath, "r") as f:
    graph_data = json.load(f)
  return {int(k): v for k, v in graph_data.items()}


def load_flag(filepath):
  with open(filepath, "r") as f:
    flag = f.readline().strip()
  return flag


def create_lwe_instance_with_error(n, m, q, error_mags):
  s = np.array([secrets.randbelow(q) for _ in range(n)], dtype=int)
  A = np.random.randint(0, q, size=(m, n), dtype=int)  # Public matrix
  e = np.array([secrets.choice([-mag, +mag]) for mag in error_mags], dtype=int)
  b = (A @ s + e) % q
  return A.tolist(), s.tolist(), e.tolist(), b.tolist()


class PathChecker:
  def __init__(
    self,
    secret_path,
    graph_data,
    lwe_error_mags,
  ):
    self.secret_path = secret_path
    self.graph = graph_data
    self.lwe_error_mags = lwe_error_mags
    self.path_len = len(self.secret_path)

  def check(self, candidate_segment):
    seg_len = len(candidate_segment)
    if seg_len > self.path_len:
      return False
    for i, node in enumerate(candidate_segment):
      if node != self.secret_path[i]:  # Node mismatch
        return False

      if i > 0:
        prev_node = candidate_segment[i - 1]
        neighbors = self.graph.get(prev_node)
        if neighbors is None or node not in neighbors:
          return False

    if seg_len == self.path_len:
      error_magnitudes = [int(abs(err_val)) for err_val in self.lwe_error_mags]
      return error_magnitudes
    else:
      return True


def main():
  flag = load_flag("flag")
  graph_data = load_graph("graph.json")
  lwe_params = LWEParams()
  if len(sys.argv) > 1:
    if sys.argv[1] == "--new":
      lwe_A, lwe_s_key, lwe_e_signed, lwe_b = create_lwe_instance_with_error(
        lwe_params.lwe_n, lwe_params.lwe_m, lwe_params.lwe_q, lwe_params.lwe_error_range
      )
      lwe_params.A = lwe_A
      lwe_params.b = lwe_b
      lwe_params.s = lwe_s_key
      lwe_params.e = lwe_e_signed
      with open("lwe_secret_params.json", "w") as s:
        json.dump(asdict(lwe_params), s, indent=2)
  else:
    with open("lwe_secret_params.json", "r") as s:
      lwe_params = json.load(s)
    lwe_A = lwe_params.get("A")
    lwe_s_key = lwe_params.get("s")
    lwe_e_signed = lwe_params.get("e")
    lwe_b = lwe_params.get("b")

  path_checker = PathChecker(
    secret_path=SECRET_HAMILTONIAN_PATH,
    graph_data=graph_data,
    lwe_error_mags=lwe_e_signed,
  )

  initial_messages = [
    "Welcome! I've hidden the key at the end of the maze. You can use this to open the chest to get the flag.",
    'Commands: {"command": "check_path", "segment": [...]}',
    '          {"command": "get_flag", "lwe_secret_s": [...] }',
  ]
  for msg in initial_messages:
    print(msg, flush=True)

  for line in sys.stdin:
    data_str = line.strip()
    if not data_str:
      continue

    response_payload = {}
    try:
      client_command = json.loads(data_str)
      command = client_command.get("command")

      if command == "check_path":
        segment = client_command.get("segment")
        if not isinstance(segment, list):
          raise TypeError("Segment must be a list.")
        path_result = path_checker.check(segment)

        if isinstance(path_result, list):
          response_payload = {
            "status": "path_complete",
            "lwe_error_magnitudes": path_result,
          }
        elif path_result is True:
          response_payload = {"status": "valid_prefix"}
        else:
          response_payload = {"status": "path_incorrect"}
      elif command == "get_flag":
        key_s_raw = client_command.get("lwe_secret_s")
        if not isinstance(key_s_raw, list):
          raise TypeError("lwe_secret_s must be a list.")

        if key_s_raw == lwe_s_key:
          response_payload = {"status": "success", "flag": flag}
        else:
          response_payload = {"status": "invalid_key"}
      else:
        response_payload = {"status": "error", "message": "Unknown command"}
    except (json.JSONDecodeError, ValueError, TypeError) as e:
      json_err = f"Invalid format or data: {e}"
      response_payload = {
        "status": "error",
        "message": json_err,
      }
    except Exception as e_cmd:
      err_mesg = f"Error processing command '{data_str}': {e_cmd}"
      response_payload = {"status": "error", "message": err_mesg}

    print(json.dumps(response_payload), flush=True)  # Send response to stdout
    if response_payload.get("flag"):
      break


if __name__ == "__main__":
  main()
```

In addition, we are also given a `lwe_pub_params.json`, where a matrix `A` and a vector `b` are stored.

:::recall
### Basic setting for Learning with error (LWE), TLDR:
Given a modulus `q`, we sample a unifomrly random matrix `A`, a secret vector `s` and a *small* error vector `e` and compute `b = As + e (mod q)`, the task here is to recover `s`.
:::

In general, we need to do the following:
- First, find the secret Hamiltonian path (which is fixed every time, so you only need to recover once)
- Then, we are given the absolute value of the error `|e|`. And we need to solve for `s`.

The first part was easy, the graph has only 30 vertices and 60 edges, so it can simply be checked by starting at 0 and then brute all the neighbors. The second part was the interesting part.

`|e|` is very large in this case, but we can modify this into an instance of LWE.

We define `A'`, `b'`, $\epsilon$ to be $A'_{ij} = A_{ij}|e_i|^{-1}$ and $b'_{i} = b_{i}|e_i|^{-1}$, and $\epsilon = sgn(e)$. So now we have: $b' = A's + \epsilon$, where $\epsilon_i \in \{-1, 1\}$, and this is another LWE.

Since the error is now small, we simply solve CVP on `b'`, and obtain the secret vector `s`.

Solution script:
```py
# solve.py
# ---- IMPORTS & SETUPS ----

from pwn import *
import json
import subprocess

# want sage?
from sage.all import *

sys.path.append('~/CTF/Crypto_Tools/crypto-attacks')

from shared.lattice import closest_vectors
import random
from sage.modules.free_module_integer import IntegerLattice

# ---- Utils & Shortcuts (Thanks @berndoj) ----

# -- simple string & bytes manipulation
byt = lambda x: x if isinstance(x, bytes) else x.encode() if isinstance(x, str) else repr(x).encode()
phex = lambda x, y='': print(y + hex(x))
lhex = lambda x, y='': log.info(y + hex(x))
pad = lambda x, s=8, v=b'\0', o='r': x+(v*(s-len(x))) if o == 'r' else x+(v*(s-len(x)))
padhex = lambda x, s: pad(hex(x)[2:], s, '0', 'l')
upad = lambda x: u64(pad(x))

# -- pwn related
io = None
gt = lambda at=None: at if at else io
sl = lambda x, io=None: gt(io).sendline(byt(x))
se = lambda x, io=None: gt(io).send(byt(x))
sla = lambda x, y, io=None: gt(io).sendlineafter(byt(x), byt(y))
sa = lambda x, y, io=None: gt(io).sendafter(byt(x), byt(y))
ra = lambda io=None: gt(io).recvall()
rl = lambda io=None: gt(io).recvline()
rlds = lambda io=None: rl(io).decode().strip()
rc = lambda x, io=None: gt(io).recv(x)
ru = lambda x, io=None: gt(io).recvuntil(byt(x))
it = lambda io=None: gt(io).interactive()
cl = lambda io=None: gt(io).close()

# -- simple number & bytes manipulation
ispr = lambda x: is_prime(x) if isinstance(x, int) else is_prime(int(x))
l2b = lambda l: long_to_bytes(l) if isinstance(l, int) else long_to_bytes(int(l))
b2l = lambda b: bytes_to_long(byt(b))
i2bv = lambda x, p=None: list(map(int, bin(x)[2:]))[::-1] if p is None else list(map(int, pad(bin(x)[2:], p, 0, l)))[::-1]
bv2i = lambda b: sum([(2**i) for i, x in enumerate(b) if x == 1])


# ---- KNOWN VARIABLES ----

def solve_pow():
    ru("with:")
    rl()
    sec = rlds().split()[-1]
    proof = subprocess.check_output(["python", "../pow.py", "solve", sec])
    ru("? ")
    sl(proof)
    rl()


def check_path(path):
    d = {"command": "check_path", "segment": path}
    sl(json.dumps(d))
    return json.loads(rlds())

def check_secret(s):
    d = {"command": "get_flag", "lwe_secret_s": s}
    sl(json.dumps(d))
    return json.loads(rlds())

d = dict()

with open("graph.json") as f:
    d = json.loads(f.read())
adj = dict()
for s in d.keys():
    adj[int(s)] = d[s]
d = adj

# ----------------------------
# ---- SOLUTION GOES HERE ----
# ----------------------------

def main() -> int:

    # Your solution here, Chad.

    # Happy pwning!
    HOST = 'filtermaze.2025.ctfcompetition.com'
    PORT = 1337
    global io
    
    # io = process(['python', 'filtermaze.py', "--new"])
    # io = process(['sage', 'filtermaze.py']) # just in case it's sage


    pub = dict()
    with open("lwe_pub_params.json") as f:
        pub = json.loads(f.read())

    A = pub["A"]
    b = pub["b"]
    q = pub["lwe_q"]

    e_abs = []

    path = [0, 15, 1, 16, 2, 17, 3, 18, 4, 19, 5, 20, 6, 21, 7, 22, 8, 23, 9, 24, 10, 25, 11, 26, 12, 27, 13, 28, 14, 29]
    e_abs = [265, 622, 38, 716, 722, 308, 996, 799, 742, 337, 927, 698, 626, 969, 330, 126, 321, 20, 271, 839, 175, 399, 752, 989, 666, 629, 271, 400, 311, 840, 821, 821, 17, 978, 488, 781, 74, 818, 849, 903, 776, 142, 505, 951, 582, 638, 222, 872, 427, 165, 307, 209, 475, 970, 748, 814, 69, 213, 27, 742, 744, 566, 262, 852, 740, 309, 997, 502, 995, 434, 405, 193, 257, 953, 924, 678, 232, 226, 560, 414, 584, 579, 767, 810, 51, 894, 446, 281, 761, 908, 715, 787, 722, 270, 94, 169, 474, 431, 292, 346]
    
    m, n = len(A), len(A[0])
    new_A = Matrix(ZZ, [[(A[i][j] * pow(e_abs[i], -1, q)) % q for j in range(n)] for i in range(m)])
    new_b = vector(ZZ, [(bb * pow(ee, -1, q)) % q for bb, ee in zip(b, e_abs)])


    D = diagonal_matrix([q] * m)
    M = block_matrix([[D], [new_A.transpose()]])
    L = IntegerLattice(M, lll_reduce=True)

    with open("M.txt", "w+") as f:
        f.write(str(M))

    new_A = Matrix(GF(q), new_A)

    io = remote(HOST, PORT)
    solve_pow()

    [rl() for _ in range(3)]

    for w in closest_vectors(L.reduced_basis, new_b, algorithm="babai"):
        s = new_A.solve_right(w)
        print(s)
        rec = check_secret([int(x) for x in s])
        if (rec["status"] == "success"):
            print(rec["flag"])

    it()

    return 0

if __name__ == '__main__':
    SystemExit(main())
```

# crypto/merkurated

>Topic: Merkle Tree, bcrypt, hash

Now this is something I didn't know at all. 

This is adapted from https://mystiz.hk/posts/2025/2025-06-30-google-ctf/#merkurated.

Challenge script:
```py
# chall.py
import sys
import signal
import hashlib
import bcrypt
import os
from ecdsa.ecdsa import Signature
from ecdsa.curves import NIST256p

def tle_handler(*args):
    print('⏰')
    sys.exit(0)

def hash(message, salt):
    h = bcrypt.hashpw(message, salt)
    _salt, h = h[:29], h[29:]
    assert salt == _salt
    return h

def recover_public_key(message, signature):
    hash = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    r, s = [int.from_bytes(signature[i:i+32], 'big') for i in range(0, 64, 32)]
    v = signature[64]

    public_keys = Signature(r, s).recover_public_keys(hash, NIST256p.generator)
    x = public_keys[v].point.x()
    return int.to_bytes(x, 32, 'big')

SALT_FOR_NODE    = bcrypt.gensalt(4)
SALT_FOR_VALUE   = bcrypt.gensalt(4)
EMPTY_NODE_HASH  = hash(b'', SALT_FOR_NODE)
EMPTY_VALUE_HASH = hash(b'', SALT_FOR_VALUE)


class RadixTree:
    def __init__(self):
        self.value = None
        self.left_subtree = None
        self.right_subtree = None
        self.cached_hash = None

    def _set(self, hash_key, value, depth=0):
        self.cached_hash = None

        if depth == 256:
            self.value = value
            return

        if hash_key & 1 == 0:
            if self.left_subtree is None:
                self.left_subtree = RadixTree()
            self.left_subtree._set(hash_key>>1, value, depth+1)
        else:
            if self.right_subtree is None:
                self.right_subtree = RadixTree()
            self.right_subtree._set(hash_key>>1, value, depth+1)

    def set(self, key, value):
        hash_key = hashlib.sha256(key).digest()
        hash_key = int.from_bytes(hash_key, 'big')
        self._set(hash_key, value)

    def _get(self, hash_key, depth=0):
        if depth == 256 and self.value is not None:
            return self.value

        if hash_key & 1 == 0 and self.left_subtree is not None:
            return self.left_subtree._get(hash_key>>1, depth+1)
        elif hash_key & 1 == 1 and self.right_subtree is not None:
            return self.right_subtree._get(hash_key>>1, depth+1)
        return 0

    def get(self, key):
        hash_key = hashlib.sha256(key).digest()
        hash_key = int.from_bytes(hash_key, 'big')
        return self._get(hash_key)

    # Show that "tree[key] = value"
    # Proof format: [value (8 bytes)][hash (31 bytes)][hash (31 bytes)]...[hash (31 bytes)]
    def verify(self, key, proof):
        hash_key = hashlib.sha256(key).digest()
        hash_key = int.from_bytes(hash_key, 'big')

        # Leaf node hash
        current_hash = hash(b':::'.join([
            EMPTY_NODE_HASH,
            EMPTY_NODE_HASH,
            hash(proof[0:8], SALT_FOR_VALUE)
        ]), SALT_FOR_NODE)

        for bit, i in zip(range(256-1, -1, -1), range(8, len(proof), 31)):
            proof_block = proof[i:i+31]
            if hash_key & (1 << bit) == 0:
                message = b':::'.join([current_hash, proof_block, EMPTY_VALUE_HASH])
                current_hash = hash(message, SALT_FOR_NODE)
            else:
                message = b':::'.join([proof_block, current_hash, EMPTY_VALUE_HASH])
                current_hash = hash(message, SALT_FOR_NODE)

        if current_hash != self.hash(): raise Exception('invalid proof')
        return int.from_bytes(proof[0:8], 'big')

    def hash(self):
        if self.cached_hash is not None:
            return self.cached_hash
        

        hash_material = []

        if self.left_subtree is not None:  hash_material.append(self.left_subtree.hash())
        else:                              hash_material.append(EMPTY_NODE_HASH)
    
        if self.right_subtree is not None: hash_material.append(self.right_subtree.hash())
        else:                              hash_material.append(EMPTY_NODE_HASH)
    
        if self.value is not None:         hash_material.append(hash(int.to_bytes(self.value, 8, 'big'), SALT_FOR_VALUE))
        else:                              hash_material.append(EMPTY_VALUE_HASH)

        message = b':::'.join(hash_material)
        self.cached_hash = hash(message, SALT_FOR_NODE)

        return self.cached_hash


def main():
    # The clock is ticking!
    signal.signal(signal.SIGALRM, tle_handler)
    signal.alarm(60)

    tree = RadixTree()
    with open('/flag.txt', 'r') as f:
      flag = f.read()

    print(f'🧂 {SALT_FOR_NODE.decode()}')
    print(f'🧂 {SALT_FOR_VALUE.decode()}')

    player_local_amount = 10**9

    while True:
        cmd, *args = input('🤖 ').strip().split(' ')
        if cmd == 'deposit':
            amount, public_key = int(args[0]), bytes.fromhex(args[1])
            if amount <= 0: raise Exception('invalid amount')
            if amount > player_local_amount: raise Exception('invalid amount')

            player_remote_amount = tree.get(public_key)

            player_local_amount -= amount
            tree.set(public_key, player_remote_amount + amount)

        elif cmd == 'withdraw':
            amount, signature, proof = int(args[0]), bytes.fromhex(args[1]), bytes.fromhex(args[2])
            if amount <= 0: raise Exception('invalid amount')
            public_key = recover_public_key(proof, signature)

            player_remote_amount = tree.verify(public_key, proof)
            if amount > player_remote_amount: raise Exception('invalid amount')

            player_local_amount += amount
            tree.set(public_key, player_remote_amount - amount)

        elif cmd == 'flag':
            if player_local_amount < 10**18: raise Exception('please earn more')
            print(f'🏁 {flag}')
            sys.exit(0)


if __name__ == '__main__':
    main()
```
:::recall
### Merkle tree, TLDR:
It's a radix tree, where each leaf contains the hash of the data blocks, and each inner node contains the hash of the informations of their children.
```text showLineNumbers=false
        Root (Top Hash)
         /   \
     H(AB)   H(CD)
     /   \    /   \
  H(A) H(B) H(C) H(D)  ← Leaves
   |    |    |    |
   A    B    C    D     ← Data Blocks
```
(Wonderful graph generated by DeepSeek)
:::

With some understanding of the Merkle tree, we need to understand what the hash funtions look like:
- The function `hash()`:
```py showLineNumbers startLineNumber=13
def hash(message, salt):
    h = bcrypt.hashpw(message, salt)
    _salt, h = h[:29], h[29:]
    assert salt == _salt
    return h
```

- Hash in the class `RadixTree`
```py showLineNumbers startLineNumber=102
    def hash(self):
        if self.cached_hash is not None:
            return self.cached_hash
        

        hash_material = []

        if self.left_subtree is not None:  hash_material.append(self.left_subtree.hash())
        else:                              hash_material.append(EMPTY_NODE_HASH)
    
        if self.right_subtree is not None: hash_material.append(self.right_subtree.hash())
        else:                              hash_material.append(EMPTY_NODE_HASH)
    
        if self.value is not None:         hash_material.append(hash(int.to_bytes(self.value, 8, 'big'), SALT_FOR_VALUE))
        else:                              hash_material.append(EMPTY_VALUE_HASH)

        message = b':::'.join(hash_material)
        self.cached_hash = hash(message, SALT_FOR_NODE)

        return self.cached_hash
```
This indicates that the hash is 

`hashpw(*left_subtree_hash*|":::"|*right_substree_hash*|":::"|hashpw(value, SALT_FOR_VALUE), SALT_FOR_NODE)`, 

the subtree hashes are replaced by `EMPTY_NODE_HASH` if they are empty.

We can of course, compute the root hash from the bottom up.

The problems with this hash are:
1. the `hash()` trims the salt (the first 29 bytes) away, and only the last 31 bytes will be taken.
2. `bcrypt` will only take the first 72 bytes of the preimage to compute the hash. So if we look at the preimage of the root hash, only the first four bytes of the value hash will be taken into account. 

So it is expected to generate $64^{4/2} = 2^{12}$ preimages to come up with a collision.

For this challenge, we need a pair of leaf node with:
- one has value x from 0 to 10^9
- the other has value y from 10^18 to 2^64
- they have the same hash

The generate idea for this challenge is now clear:
- Generate an ECDSA key
- Generate two leaf nodes with the above properties
- Call `deposit(x, public_key)` to create the first node in the tree
- Generate a proof to show that `tree[public_key] = y`
- Sign the proof with ECDSA private key
- Call `withdraw(y, private_key, proof)` to withdraw y.

As long as the difference of x and y is large enough, we can just get the flag.

My own solution: TODO

# crypto/underhanded

>Topic: AES, Differential analysis

# crypto/sphinx

>Topic: Khafre, Differential analysis

Man, there are a lot of differential analysis this year.

We are given a script with lots of Egyptian symbols, but DeepSeek and friends simplied lots of jobs for us. The unEgypted script looks a bit like this:

```py
# sphinx_vibe_decoded.py
import struct
import os
import base64

FLAG = base64.b16encode(b"fakeflag")

# DES Pi constant (large decimal number used for S-box generation)
DES_PI = (
    "10097325337652013586346735487680959091173929274945375420480564894742962480524037"
    # omitted for brevity
    "0039758391126071764648949723069454137408775130382086864299016841482774"
)

# DES rotation amounts for each round
rotation_amounts = [16, 16, 8, 8, 16, 16, 24, 24]
initialization_rounds = 2
max_rounds = 8

def rotate_left(value, shift_bits):
    return ((value << shift_bits) & 0xFFFFFFFF) | (value >> (32 - shift_bits))

def rotate_right(value, shift_bits):
    return ((value >> shift_bits) | (value << (32 - shift_bits))) & 0xFFFFFFFF

def bits_to_int(byte_data):
    if len(byte_data) % 4 != 0:
        raise ValueError("Byte string length must be a multiple of 4.")
    return list(struct.unpack(">%dI" % (len(byte_data) // 4), byte_data))

def int_to_bits(int_list):
    return struct.pack(">%dI" % len(int_list), *int_list)

class PRNG:
    def __init__(self):
        self.position = 0

    def digit(self):
        if self.position >= len(DES_PI):
            raise IndexError("DES PI string exhausted")
        value = ord(DES_PI[self.position]) - ord('0')
        self.position += 1
        return value

    def in_range(self, low, high):
        range_value = (high - low) + 1
        while True:
            random_num = 0
            max_value = 1
            while max_value < range_value:
                max_value *= 10
                random_num = (random_num * 10) + self.digit()

            if random_num < ((max_value // range_value) * range_value):
                break
        return low + (random_num % range_value)

def swap_bits_in_sbox(sbox, row1, row2, column):
    bits_shift = (3 - column) * 8
    mask = (0xff << bits_shift) & 0xFFFFFFFF

    temp_value = sbox[row1]
    sbox[row1] = (sbox[row1] & (~mask & 0xFFFFFFFF)) | (sbox[row2] & mask)
    sbox[row2] = (sbox[row2] & (~mask & 0xFFFFFFFF)) | (temp_value & mask)


def des_transform_words(left, right, des_sboxes, aux_keys, rounds=16):
    left = (left ^ aux_keys[0]) & 0xFFFFFFFF
    right = (right ^ aux_keys[1]) & 0xFFFFFFFF

    octets = rounds // 8
    for octet_idx in range(octets):
        sbox_to_use = des_sboxes[octet_idx]
        for r_idx in range(8):
            right = (right ^ sbox_to_use[left & 0xff]) & 0xFFFFFFFF
            left = rotate_right(left, rotation_amounts[r_idx])
            left, right = right, left

    left = (left ^ aux_keys[2]) & 0xFFFFFFFF
    right = (right ^ aux_keys[3]) & 0xFFFFFFFF
    return [left, right]

def generate_key_words(key_words_input, id_input, aux_keys_for_des, internal_des_sboxes):
    key_words = list(key_words_input)
    id_words = list(id_input)
    result = [0] * len(key_words)

    for position in range(0, len(key_words), 2):
        left = (key_words[position] ^ id_words[0]) & 0xFFFFFFFF
        right = (key_words[position+1] ^ id_words[1]) & 0xFFFFFFFF

        id_words = des_transform_words(left, right, internal_des_sboxes, aux_keys_for_des, 16)

        result[position] = id_words[0]
        result[position+1] = id_words[1]
    return result

def key_material_from_words(key_words_input, num_sboxes_to_gen, base_internal_sbox):
    key_words = list(key_words_input)

    internal_des_sboxes_for_ks = [list(base_internal_sbox) for _ in range(initialization_rounds)]

    id_words = [key_words[-2], key_words[-1]]
    zero_aux_keys = [0, 0, 0, 0]

    for _ in range(3):
        key_words = generate_key_words(key_words, id_words, zero_aux_keys, internal_des_sboxes_for_ks)
        id_words = [key_words[-2], key_words[-1]]

    final_aux_keys = key_words[0:4]

    output_sboxes = [list(base_internal_sbox) for _ in range(num_sboxes_to_gen)]

    key_bits_count = 16

    for sbox_idx in range(num_sboxes_to_gen):
        for column_idx in range(4):
            current_mask = 0xff
            smaller_mask = current_mask >> 1

            for row_idx in range(255):
                random_row = 0
                while True:
                    shift_value = (3 - (key_bits_count & 3)) * 8
                    key_word_idx = key_bits_count >> 2
                    extracted_value = (key_words[key_word_idx] >> shift_value) & current_mask

                    random_row = row_idx + extracted_value
                    key_bits_count += 1

                    if key_bits_count > 63:
                        key_bits_count = 0
                        key_words = generate_key_words(key_words, id_words, zero_aux_keys, internal_des_sboxes_for_ks)
                        id_words = [key_words[-2], key_words[-1]]

                        current_mask = 0xff
                        smaller_mask = current_mask >> 1
                        while smaller_mask > 0 and (((255 - row_idx) & (~smaller_mask & 0xFFFFFFFF))) == 0:
                            current_mask = smaller_mask
                            smaller_mask >>= 1

                    if random_row <= 255:
                        break

                swap_bits_in_sbox(output_sboxes[sbox_idx], row_idx, random_row, column_idx)

    return {'sboxes': output_sboxes, 'auxkeys': final_aux_keys}


def pre_compute_internal_standard_sbox():
    rand = PRNG()
    sbox0 = [(0x01010101 * r) & 0xFFFFFFFF for r in range(256)]
    for column in range(4):
        for row in range(255):
            swap_bits_in_sbox(sbox0, row, rand.in_range(row, 255), column)
    return sbox0

def get_standard_sboxes_for_des():
    internal_s0 = pre_compute_internal_standard_sbox()
    zero_key_words = [0] * 16

    derived_material = key_material_from_words(
        key_words_input=zero_key_words,
        num_sboxes_to_gen=max_rounds,
        base_internal_sbox=internal_s0
    )
    all_derived_sboxes = derived_material['sboxes']

    final_sboxes_for_des = [internal_s0] + all_derived_sboxes[:7]

    return final_sboxes_for_des


class DES:
    standard_des_sboxes = None
    template = None

    @staticmethod
    def _initialize_sboxes():
        if DES.standard_des_sboxes is None:
            DES.standard_des_sboxes = get_standard_sboxes_for_des()

    def __init__(self, key: bytes, rounds=16):
        DES._initialize_sboxes()

        if not (8 <= rounds <= 64 and rounds % 8 == 0):
            raise ValueError("rounds must be between 8 and 64 and a multiple of 8.")
        self.rounds = rounds

        if not (len(key) >= 8 and len(key) % 8 == 0):
            raise ValueError("key length must be a multiple of 8 bytes and at least 8 bytes.")

        self.keys = bits_to_int(key)
        self.sboxes = DES.standard_des_sboxes

        num_key_blocks_64bit = len(self.keys) // 2
        if num_key_blocks_64bit == 0:
             raise ValueError("key is too short for compatibility check.")

        if ((self.rounds // 8) + 1) % num_key_blocks_64bit != 0:
            raise ValueError("key size incompatible with number of rounds for key whitening schedule.")


    def encrypt_block(self, block: bytes, is_template=False, debug=False) -> bytes:
        if len(block) != 8:
            raise ValueError("block size must be 8 bytes.")
        if is_template:
          self.template = [None] * self.rounds
        else:
          self.last = [None] * self.rounds

        left, right = bits_to_int(block)

        keys = self.keys
        sboxes = self.sboxes

        num_sbox_octets = self.rounds // 8

        key_idx = 0
        current_sbox_octet_idx = 0

        while True:
            if key_idx >= len(keys):
                key_idx = 0

            left  = (left  ^ rotate_right(keys[key_idx], current_sbox_octet_idx)) & 0xFFFFFFFF
            right = (right ^ rotate_right(keys[key_idx+1], current_sbox_octet_idx)) & 0xFFFFFFFF
            key_idx += 2

            if current_sbox_octet_idx >= num_sbox_octets:
                break

            sbox_to_use = sboxes[current_sbox_octet_idx]
            for r_idx in range(8):
                old_left = left
                old_right = right
                sbox_idx = left & 0xff
                sbox_output = sbox_to_use[sbox_idx]
                right = (right ^ sbox_output) & 0xFFFFFFFF
                left = rotate_right(left, rotation_amounts[r_idx])
                left, right = right, left
                if is_template:
                  self.template[current_sbox_octet_idx * 8 + r_idx] = (old_right, old_left, sbox_idx, sbox_output)
                else:
                  self.last[current_sbox_octet_idx * 8 + r_idx] = (old_right, old_left, sbox_idx, sbox_output)

            current_sbox_octet_idx += 1

        return int_to_bits([left, right])

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            raise ValueError("block size must be 8 bytes.")
        left, right = bits_to_int(block)

        keys = self.keys
        sboxes = self.sboxes

        num_sbox_octets = self.rounds // 8

        num_key_pairs = len(keys) // 2
        last_key_pair_start_idx_in_encrypt = (num_sbox_octets % num_key_pairs) * 2
        key_idx = last_key_pair_start_idx_in_encrypt


        current_sbox_octet_idx = num_sbox_octets

        while True:
            left  = (left  ^ rotate_right(keys[key_idx], current_sbox_octet_idx)) & 0xFFFFFFFF
            right = (right ^ rotate_right(keys[key_idx+1], current_sbox_octet_idx)) & 0xFFFFFFFF

            if current_sbox_octet_idx == 0:
                break

            key_idx -= 2
            if key_idx < 0:
                key_idx = len(keys) - 2

            current_sbox_octet_idx -= 1

            sbox_to_use = sboxes[current_sbox_octet_idx]
            for r_idx in reversed(range(8)):
                left, right = right, left
                left = rotate_left(left, rotation_amounts[r_idx])
                right = (right ^ sbox_to_use[left & 0xff]) & 0xFFFFFFFF

        return int_to_bits([left, right])

banner="""
╭────────────────────────────────────────────╮██████████▀▀▀▀▀▀▀███████████
│       As the petrine nexus and chronophage,│████████▀ █ ▀ █ ▀  ▀████████
│    your transient being shall I now engage.│███████▀ ▄▄▄▄▄▄▄ ▀▀ ▀███████
│         This presented morphoglyphic array │██████▀  ▄ ▄▄▄▄▄ ▀▀▀ ▀██████
│             is but a gnostologic semioxiom.│██████ ▀ ▄ █▄ ▄█ ▀▀▀▀  █████
│      You must vervold the latent cryptolex,│█████ ▀▀ █ ▀███▀ ▀▀▀▀▀ █████
│       and quintignify its integral meaning.│█████ ▀▀  █▀▀█▀  ▀▀▀▀ ▄█████
│              Should your answers please me,│██████ ▀▀ ▀▀▀ ▄ ▀▀▀  ▄▄ ▀███
│          I shall bestow upon you my banner.│██████ ▀▀  ▀ █▀ ▀▀ ▄████▄ ▀█
│ Should they be found wanting, your essence │█████▀ ▀▀ ████ ▀▀ ▄██ ███  █
│            will be inexorably subliminated.│██▀ ▄▄██▀██▀▀ ▄▄▄███  ▀▀▀█ █
╰──────────────────────────────────────────╮╭╯█ ▄▀▄█   ▀ ▄▀█▀████▀  ▀▀▀▀ █
                                           ╰╯ █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄██
"""
print(banner)

key = DES(os.urandom(8))
challenge = base64.b16encode(key.encrypt_block(base64.b16decode(FLAG)))
print("I say you: ", challenge.decode())
while True:
    try:
        print("You say I: ", end="")
        response = base64.b16decode(input())
        decoded_response=base64.b16encode(key.encrypt_block(response))
        if decoded_response==challenge:
            print("""
    ██████████████╭────────────────────────────────────────────╮
    ██████████████│ at last - my chronal purpose has devolved  │
    ██████████████│ be you now sealed by this glyph            │
    ██████████████│     CTF{%s}                  │
    ██████████████│ my station now becomes your monolith       │
    ██████████████╰╮╭──────────────────────────────────────────╯
    ██████████████ ╰╯
    """%base64.b16encode(key.decrypt_block(key.encrypt_block(response))).decode())
            break
        else:
            print("I say you: ", decoded_response.decode())
    except ValueError as e:
        print("You said wrong.")
```
from Crypto.Random        import random
from Crypto.Hash          import SHA3_256
from Crypto.Hash.SHA3_256 import SHA3_256_Hash
from Crypto.Hash          import SHA3_512
from Crypto.Hash.SHA3_512 import SHA3_512_Hash


def hex_to_int(hex:str) -> int:
  return int(hex, 16)


def sha3_256_hash(data:bytes) -> str:
  H: SHA3_256_Hash = SHA3_256.new(data)
  return H.hexdigest()


def sha3_512_hash(data:bytes) -> str:
  H: SHA3_512_Hash = SHA3_512.new(data)
  return H.hexdigest()


def Init(bitlen:int = 256) -> tuple[int, int, int]:
  q: int = random.getrandbits(bitlen)
  g: int = random.getrandbits(bitlen) % q
  h: int = random.getrandbits(bitlen) % q

  while (g**2 % q == 1):
    g = random.getrandbits(bitlen) % q

  return q, g, h



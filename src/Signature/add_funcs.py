from Crypto.Random        import random
from Crypto.Hash          import SHA3_256
from Crypto.Hash.SHA3_256 import SHA3_256_Hash


def hex_to_int(hex:str) -> int:
  return int(hex, 16)


def sha3_256_hash(data:bytes) -> str:
  H: SHA3_256_Hash = SHA3_256.new(data)
  return H.hexdigest()


def Init(bitlen:int = 256) -> tuple[int, int, int]:
  q: int = random.getrandbits(bitlen)
  g: int = random.getrandbits(bitlen) % q
  h: int = random.getrandbits(bitlen) % q

  while (g**2 % q == 1):
    g = random.getrandbits(bitlen) % q

  return q, g, h
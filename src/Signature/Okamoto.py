from Crypto.Random  import random
from math           import log2, ceil
from add_funcs      import sha3_256_hash, hex_to_int

class SecretKey:
  def __init__(self, a:int, b:int, a_t:int, b_t:int):
    self.__a    = a
    self.__b    = b
    self.__a_t  = a_t
    self.__b_t  = b_t

  def A (self):
    return self.__a
  def B (self):
    return self.__b
  def At(self):
    return self.__a_t
  def Bt(self):
    return self.__b_t
    

class PublicKey:
  def __init__(self, u:int, u_t:int):
    self.__u    = u
    self.__u_t  = u_t

  def U (self):
    return self.__u
  def Ut(self):
    return self.__u_t



class OkamotoSign:
  # private

  def __get_bit_len(self, number: int) -> int:
    k: int = ceil(log2(number.bit_length()))
    return 2**k

  # public
  def __init__(self, q:int, g:int, h:int):
    self.__q = q
    self.__g = g
    self.__h = h
  

  def KeyGen(self) -> tuple[SecretKey, PublicKey]:
    bitlen: int = self.__get_bit_len(self.__q)
    a:      int = random.getrandbits(bitlen) % self.__q
    b:      int = random.getrandbits(bitlen) % self.__q
    a_t:    int = a
    b_t:    int = b
    
    while (a_t == a) or (b_t == b):
      if a_t == a:
        a_t = random.getrandbits(bitlen) % self.__q
      if b_t == b:
        b_t = random.getrandbits(bitlen) % self.__q
    
    u:      int = ( self.__g**a    *  self.__h * b   ) % self.__q
    u_t:    int = ( self.__g**a_t  *  self.__h * b_t ) % self.__q

    sk: SecretKey = SecretKey(a, b, a_t, b_t)
    pk: PublicKey = PublicKey(u, u_t)

    return sk, pk


  def Sign(self, message: str, sk:SecretKey) -> int:
    c:   int = hex_to_int(sha3_256_hash(message.encode('utf-8')))
    a_z: int = ( sk.At() + sk.A() * c ) % self.__q
    b_z: int = ( sk.Bt() + sk.B() * c ) % self.__q
    u_z: int = ( self.__g**a_z * self.__h * b_z ) % self.__q

    return u_z
  
  def Verify(self, message: str, signature: int, pk:PublicKey) -> bool:
    c:   int = hex_to_int(sha3_256_hash(message.encode('utf-8')))
    rhs: int = pk.Ut() * pk.U()**c % self.__q
    return (signature == rhs)
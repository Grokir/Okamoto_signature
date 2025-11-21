from Crypto.Random  import random
from math           import log2, ceil
from .add_funcs     import sha3_256_hash, hex_to_int

class SecretKey:
  def __init__(self, a:int, b:int):
    self.__a    = a
    self.__b    = b

  def A (self):
    return self.__a
  def B (self):
    return self.__b


class PublicKey:
  def __init__(self, u:int):
    self.__u    = u

  def U (self):
    return self.__u
    

class Signature:
  def __init__(self, a_z:int, b_z:int, u_t:int):
    self.__a_z  = a_z
    self.__b_z  = b_z
    self.__u_t  = u_t

  def Az (self):
    return self.__a_z
  
  def Bz (self):
    return self.__b_z
  
  def Ut (self):
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
    u:      int = ( pow(self.__g, a, self.__q) * pow(self.__h, b, self.__q) ) % self.__q
    
    sk: SecretKey = SecretKey(a, b)
    pk: PublicKey = PublicKey(u)

    return sk, pk


  def Sign(self, message: str, sk:SecretKey) -> Signature:
    c:      int = hex_to_int(sha3_256_hash(message.encode('utf-8')))
    bitlen: int = self.__get_bit_len(self.__q)
    a_t:    int = sk.A()
    b_t:    int = sk.B()
    
    while (a_t == sk.A()) or (b_t == sk.B()):
      if a_t == sk.A():
        a_t = random.getrandbits(bitlen) % self.__q
      if b_t == sk.B():
        b_t = random.getrandbits(bitlen) % self.__q

    a_z: int = ( a_t + sk.A() * c )
    b_z: int = ( b_t + sk.B() * c )
    u_t: int = ( pow(self.__g, a_t, self.__q) * pow(self.__h, b_t, self.__q) ) % self.__q

    return Signature(a_z, b_z, u_t)
  

  def Verify(self, message: str, signature: Signature, pk:PublicKey) -> bool:
    c:   int = hex_to_int(sha3_256_hash(message.encode('utf-8')))
    lhs: int = ( 
      pow(self.__g, signature.Az(), self.__q) * 
      pow(self.__h, signature.Bz(), self.__q) 
    ) % self.__q

    rhs: int = ( signature.Ut() * pow(pk.U(), c, self.__q) ) % self.__q
    return (lhs == rhs)
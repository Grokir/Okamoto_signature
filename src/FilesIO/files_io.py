from Signature.Okamoto    import SecretKey, PublicKey
from Signature.add_funcs  import sha3_256_hash

def save_keypair    (sk: SecretKey, pk: PublicKey, path_to_dir:str) -> bool:
  try:
  
    with open(path_to_dir+"okamoto_key", 'w') as sk_file:
      sk_file.write(f"{sk.A()}\n{sk.B()}\n{sk.At()}\n{sk.Bt()}")

    with open(path_to_dir+"okamoto_key.pub", 'w') as pk_file:
      pk_file.write(f"{pk.U()}\n{pk.Ut()}")

  except:
    return False

  return True


def load_keypair    (path_to_dir:str) -> tuple[SecretKey, PublicKey]:
  sk_list: list[str] = []
  pk_list: list[str] = []

  with open(path_to_dir+"okamoto_key", 'r') as sk_file:
    sk_list = sk_file.readlines()

  with open(path_to_dir+"okamoto_key.pub", 'r') as pk_file:
    pk_list = pk_file.readlines()

  sk: SecretKey = SecretKey(
    a   = int(sk_list[0]),
    b   = int(sk_list[1]),
    a_t = int(sk_list[2]),
    b_t = int(sk_list[3])
  )

  pk: PublicKey = PublicKey(
    u   = int(pk_list[0]),
    u_t = int(pk_list[2])
  )

  return sk, pk


def load_private_key(path_to_dir:str) -> SecretKey:
  sk_list: list[str] = []

  with open(path_to_dir+"okamoto_key", 'r') as sk_file:
    sk_list = sk_file.readlines()

  sk: SecretKey = SecretKey(
    a   = int(sk_list[0]),
    b   = int(sk_list[1]),
    a_t = int(sk_list[2]),
    b_t = int(sk_list[3])
  )

  return sk


def load_public_key (path_to_dir:str) -> PublicKey:
  pk_list: list[str] = []

  with open(path_to_dir+"okamoto_key.pub", 'r') as pk_file:
    pk_list = pk_file.readlines()

  pk: PublicKey = PublicKey(
    u   = int(pk_list[0]),
    u_t = int(pk_list[1])
  )
  # print(f"u   = {int(pk_list[0])},\nu_t = {int(pk_list[1])}")

  return pk




def save_signature(signature:int, path_to_sign:str):
  try:
  
    with open(path_to_sign, 'w') as sign_file:
      sign_file.write(str(signature))

  except:
    return False

  return True


def load_signature(path_to_sign:str) -> int:
  sign: int = -1
  
  with open(path_to_sign, 'r') as sign_file:
    sign = int(sign_file.readline())

  return sign


def block_read_file(path_to_file: str) -> str:
  res_data: str     = ""
  data:     bytes   = bytes()
  with open(path_to_file, 'rb') as f:
    while True:
      data = f.read(1024)
      if not data:
        break
      res_data += sha3_256_hash(data)

  return res_data
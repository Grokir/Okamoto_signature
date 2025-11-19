from sys import argv


# project modules
from Config             import config
from Signature          import add_funcs
from Signature.Okamoto  import OkamotoSign
from FilesIO            import files_io as fio
from tests              import test_valid, test_invalid  

def help() -> None:
  print("""
  --test
  --help
  --init-config
  --keygen        <path to dir with keys> 
  --signature     <path to message> <path to dir with secret key>
  --verify        <path to message> <path to dir with sign>  <path to dir with public key>
""")
  

def main():
  if "--test" in argv:
    test_valid()
    test_invalid()
    return

  q: int = -1
  g: int = -1
  h: int = -1


  if "--init-config" in argv:
    q, g, h                             = add_funcs.Init()
    yml_data: dict[str, dict[str, str]] = {
      'params': {
        'q': hex(q), 
        'g': hex(g), 
        'h': hex(h)
      }
    }
    config.write("./config.yml", yml_data)
  else:
    load: dict[str, dict[str, str]] = config.read("./config.yml")
    q = int(load['params']['q'], 16)
    g = int(load['params']['g'], 16)
    h = int(load['params']['h'], 16)

  sign_device: OkamotoSign = OkamotoSign(q, g, h)

  cmd: str = argv[1] if len(argv) > 1 else ""

  match cmd:
    case "--help":
      help()

    case "--keygen":
      path_to_keys: str = argv[2] if len(argv) > 2 else "./"
      sk, pk = sign_device.KeyGen()
      if fio.save_keypair(sk, pk, path_to_keys):
        print(f"Keys save to '{path_to_keys}'!")
      else:
        print("Error: keys save is failed!")

    
    case "--signature":
      print("Document signing start...")
      path_to_msg:  str = argv[2]
      path_to_key:  str = argv[3]
      sign:         int = sign_device.Sign(
        fio.block_read_file (path_to_msg),
        fio.load_private_key(path_to_key)
      )
      fio.save_signature(sign, path_to_msg + ".sig");
      print("The document is signed!")  
    

    case "--verify":
      print("Document verification start...")
      path_to_msg = argv[2]
      path_to_sig = argv[3]
      path_to_key = argv[4]

      verify_flag: bool = sign_device.Verify(
        fio.block_read_file(path_to_msg),
        fio.load_signature (path_to_sig),
        fio.load_public_key(path_to_key)
      )

      print("Document verification: ", end='')
      if(verify_flag):
        print("SUCCESS")
      else:
        print("FAIL")

    case _:
      print("Error: invalid argument!")
      print(f"Execute {argv[0]} with argument '--help'.")



if __name__ == "__main__":
  main()
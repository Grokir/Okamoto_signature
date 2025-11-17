from Config             import config
from Signature.Okamoto  import OkamotoSign


def test():
  print("[test signature]: ", end='')
  msg:  str = "Hello world!"
  load: dict[str, dict[str, str]] = config.read("./config.yml")
  q:    int = int(load['params']['q'], 16)
  g:    int = int(load['params']['g'], 16)
  h:    int = int(load['params']['h'], 16)

  sign_device: OkamotoSign = OkamotoSign(q, g, h)
  sk, pk    = sign_device.KeyGen()
  sign: int = sign_device.Sign(msg, sk)
  
  if(sign_device.Verify(msg, sign, pk)):
    print("OK")
  else:
    print("FAIL")
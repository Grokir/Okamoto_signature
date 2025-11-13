import yaml

def read(path_to_conf: str) -> dict[str, dict[str, str]]:
  res: dict[str, dict[str, str]] = {}
  with open(path_to_conf, 'r') as file:
    res = dict(yaml.safe_load(file))
  return res


def write(path_to_conf: str, data: dict) -> None:
  with open(path_to_conf, 'w') as file:
    yaml.dump(data, file)

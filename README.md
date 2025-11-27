# Подпись Окамото / Okamoto signature

# Авторы / Authors
 - [Grokir](https://github.com/Grokir)
 - [Konstantin A.S.](https://github.com/KonstantinSaperov)




## Подготовка / Preparation
```
git clone https://github.com/Grokir/Okamoto_signature.git
cd Okamoto_signature
pip install -r requirements.txt  
```

## Использование / Usage
```
cd Okamoto_signature/src
```
### Запуск / Run
```
python main.py --help

  --test
  --help
  --init-config
  --keygen        <path to dir with keys> 
  --signature     <path to message> <path to dir with secret key>
  --verify        <path to message> <path to dir with sign>  <path to dir with public key>

```

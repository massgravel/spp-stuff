from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5s
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA1, HMAC
from Crypto.Random import get_random_bytes
from sys import argv

SPP_PROD_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDXsWBAi5fZLtghWfw8h436oA2jj9NRtXwIflPNtfCZajhZUjie
lWojg02FFWw/QgKAymqXWOACbvl1kME9PNFMKP42LQNci+TpaGWj8KUr9+llQ7c5
FD1WYETdxd5BAB6GBWVRQjM6YbgR4/WL3U8IZ/k7sjhrJhLYV5BSP7qHKQIDAQAB
AoGBAL84RIHUf9GOYxPmR+WNs4RuosjPuGOnBogtHrSvyNbpwX0GlKWbBxbm0DHd
FTNbnQZ67Vax9x6RLd1ZcMeOhGljjawdN1J69svKdGEfLgk6ZjwY/IK1R+lhcNm6
6wq7lGZubHks+v4bfoIgNU6PSyrVguMUKyCIZI9UmNLXISbVAkEA2BvXsM7ByJx1
3UgjmQIIoYJLihaJxxR7VIXZG7k4Q5IE89tSUxNqgPr/KF5MlOBc4U1a3LfkV7E8
zFC1YG4KKwJBAP+B4YPO+6233rd/Ua73QyXVAAp1rY/ZD/LYnfV/x5tew6HutDIK
DeDwQ+FAnpbOH6e6MzBEaSn2SxinRy6nLfsCQAK15rCrBzcy7y+FVhz3L5CHB9eF
jNjYYuueeiik3BXM4Q8F8zRji/RuMYEaHa/IWKHizH70N4L6EB8n6/53ot0CQFhQ
EB564Eq/Dt/lxdnv5OmioYz7962MnRKXBKHiNJ/jNUM3OllBWGKzKQMmTqpZPF/A
4AiC3MaANpyi1NuvNRkCQQCr+LBFMuA05e901DwL24dMQsHsd3IDaXaf+ZBImg+M
60aHSrllG6RLV/Sk5lgKWCUvrIJ97Yza156wV/7U4VFj
-----END RSA PRIVATE KEY-----"""

VERSION = 5

ciph = PKCS1_v1_5.new(RSA.import_key(SPP_PROD_KEY))
sig = PKCS1_v1_5s.new(RSA.import_key(SPP_PROD_KEY))

f = open(argv[1], "rb")
ts_data = f.read()

aeskey = b"massgrave.dev :3"
hmackey = b"untrustedstore  "

enc_aeskey = ciph.encrypt(aeskey)
aeskey_sig = sig.sign(SHA1.new(enc_aeskey))
hmac = HMAC.new(hmackey, ts_data, SHA1)
hmac_sig = hmac.digest()

header = VERSION.to_bytes(4, "little") + b"UNTRUSTSTORE" + aeskey_sig + enc_aeskey
data = hmackey + hmac_sig + b"\x00\x00\x00\x00" + ts_data

aes = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16)
encr_data = aes.encrypt(pad(data, AES.block_size))

with open(argv[2], "wb") as g:
    g.write(header + encr_data)
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5s
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA1, HMAC
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

ciph = PKCS1_v1_5.new(RSA.import_key(SPP_PROD_KEY))
sig = PKCS1_v1_5s.new(RSA.import_key(SPP_PROD_KEY))

f = open(argv[1], "rb")
f.seek(0x10)

aesk_sig = f.read(0x80)

f.seek(0x90)
aes_data = f.read(0x80)

if sig.verify(SHA1.new(aes_data), aesk_sig):
    aeskey = ciph.decrypt(aes_data, 0)
    aes = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16)

    f.seek(0x110)
    decr_data = unpad(aes.decrypt(f.read()), AES.block_size)
    
    hmac_key = decr_data[:0x10]
    hmac_sig = decr_data[0x10:0x24]
    ts_data = decr_data[0x28:]
    
    try:
        hmac = HMAC.new(hmac_key, ts_data, SHA1)
        #hmac.verify(hmac_sig)
        
        with open(argv[2], "wb") as fw:
            fw.write(ts_data)
    except ValueError:
        print("!!! BAD HMAC !!!")
else:
    print("!!! BAD SIGNATURE !!!")
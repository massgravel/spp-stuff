# Decrypt C:\Windows\System32\spsys.log from Windows 7
# Can be used to trace functions executed in spsys

from Crypto.Cipher import AES
from struct import unpack

aeskey = bytes([0x5B, 0x68, 0x49, 0x25, 0x79, 0x7B, 0x81, 0xFE, 0x5C, 0x44, 0x1B, 0x08, 0x2B, 0xEA, 0xEC, 0x4E])

log_data = b""

with open("spsys.log", "rb") as f:
    aes = AES.new(aeskey, AES.MODE_ECB)
    log_data = aes.decrypt(f.read()[0x28:])

with open("spsys_log_d.bin", "wb") as f:
    f.write(log_data)
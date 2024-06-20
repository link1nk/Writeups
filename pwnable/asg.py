from pwn import *

context(arch="amd64", os="linux", endian="little")

sh = ssh("asg", "pwnable.kr", password="Mak1ng_shelLcodE_i5_veRy_eaSy", port=2222)
r = sh.remote("0", 9025)



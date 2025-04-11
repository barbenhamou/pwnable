#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./enchantment')

host = args.HOST or 'pwnable.co.il'
port = int(args.PORT or 9011)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

try:
    while True:
        print("> ", end="", flush=True)  # manually print prompt
        inp = input().strip()
        if inp in ("open", "close", "check"):
            inp += " 0"
        io.sendline(inp.encode())
        resp = io.recvuntil(b'>')
        print(resp.decode().replace(">", "").strip())
except (EOFError, KeyboardInterrupt):
    print("\nExiting...")

io.interactive()



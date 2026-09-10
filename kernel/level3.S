;  
;    This simple program will run from the MBR of a virtual disk.
;    It will run in real mode, and it will communicate over the serial port.
;    The user will be able to Read, Write or Call 16-bit values using an offset from an array in memory.
;    This is intended as an example of how to shellcode in real mode, with the goal of reading the virtual disk using BIOS APIs.
;  

org 0x7c00
bits 16

setup:
    mov sp, 0x8002
    mov ax, 0xfeeb
    push ax
    jmp main
    db 00, 00, 00

USERMEM equ 0x6000
COM_BUFFER equ 0x7000
COM_BUFFER_SIZE equ 64

main:
    cmp bx, 0x60d2 ; slot is 0x69
    jne main_no_easter_egg
        mov ax, EASTER_EGG_STR
        call puts
    main_no_easter_egg:

    call get_command


    mov bx, dx
    shl bx, 1
    add bx, USERMEM ; slot address in bx

    push bx

    cmp al, 0
    je main_read
    cmp al, 1
    je main_write
    cmp al, 2
    je main_call

    main_read:
        mov ax, word [bx]
        call xprint_word
        jmp main_end
    main_write:
        call get_xword
        mov word [bx], dx
        jmp main_end
    main_call:
        call deny
    
    main_end:
    pop bx  ; if `call deny` does not get called, stack leaks by 2 bytes
            ; we control those 2 bytes though, and this makes the exploit possible
    jmp main

deny:
    mov ax, NO_YOU_CANT
    push main
    jmp puts
    ; bug here, can call main -> deny -> main -> deny -> ... to stack overflow
    ; the distance is 0x8000 - 0x7c00 = 0x400, and for each call 4 extra bytes are pushed
    ; 2 for the return address, 2 for the pushed bx which is never popped
    ; so at most 0x400 / 4 = 0x100 calls can be made before the stack overflows
    ; realistically we will reach code much earlier, as code can be up to 0x200 (512) bytes long
    
    ; 46 7c 66 90 46 7c 00 5b 46 7c 00 c3 works if jl does not take, in getc (might have to adjust for offsets)

NO_YOU_CANT db 0x0a, "Sorry, management blocked execute calls", 0
EASTER_EGG_STR db 0x0a, "(hehe funny number)", 0

; FUNCTIONS
; Calling convention is param1 = a, param2 = d ; b is preserved
; Params can also be retvals depending on the function

; On next levels, 'X' should not be an option, the user will have to gain control flow by overwriting instructions/stack
CMD_PROMPT db 0x0a, "[R|W|X] [slot_number hexword]> ", 0
get_command:    ; char, short get_command()
                ; returns 0 for read, 1 for write, 2 for call
    call newline      
    mov ax, CMD_PROMPT
    call puts
    mov ax, COM_BUFFER
    mov dx, COM_BUFFER_SIZE
    call getsn
    mov al, byte [COM_BUFFER]
    or al, 0x20 ; lowercase
    cmp al, 'r'
    je get_command_read
    cmp al, 'w'
    je get_command_write
    cmp al, 'x'
    je get_command_call
    jmp get_command ; invalid command, try again

    get_command_read:
        mov si, 0
        jmp get_command_get_slot
    get_command_write:
        mov si, 1
        jmp get_command_get_slot
    get_command_call:
        mov si, 2
        
    get_command_get_slot:
    mov ax, word [COM_BUFFER + 2]
    mov dx, word [COM_BUFFER + 4]
    call hexstr_to_word
    mov dx, ax
    mov ax, si
    ret

XW_PROMPT db 0x0a, "[hexword]> ", 0
get_xword: ; short get_xword() WARN: returns in dx
    mov ax, XW_PROMPT
    call puts

    mov ax, COM_BUFFER + 2
    mov dx, COM_BUFFER_SIZE - 2
    call getsn
    jmp get_command_get_slot

xprint_word: ; void xprint_word(short)
    push bx
    mov bx, ax
    shr ax, 8
    call xprint_byte
    mov ax, bx
    call xprint_byte
    pop bx
    ret

xprint_byte: ; void xprint_byte(char)
    push ax
    shr al, 4
    call xprint_byte_nib
    pop ax
    and al, 0x0f
    xprint_byte_nib:
        cmp al, 0xa
        jl xprint_byte_nib_dec
            add al, 0x7
        xprint_byte_nib_dec:
            add al, 0x30
        jmp putc

; This is going to be crude and buggy, who cares lol
hexstr_to_word: ; short hexstr_to_word(char[2] high, char[2] low)
    mov di, bx
    push ax
    call hexstr_to_word_do_byte
    shr ax, 8
    pop dx
    call hexstr_to_word_do_byte
    mov bx, di
    ret

    hexstr_to_word_do_byte: ; dl(char) -> ah(value)
        mov bl, dh
        call hexstr_to_word_do_nibble
        mov ah, cl
        mov bl, dl
        call hexstr_to_word_do_nibble
        shl cl, 4
        or ah, cl
        ret

    hexstr_to_word_do_nibble: ; bl(char) -> cl(value)
        xor cl, cl
        bt bx, 6 ; if bl is a letter sets CF
        jnc hexstr_to_word_dec_n
            add cl, 9
        hexstr_to_word_dec_n:
            and bl, 0x0f
            add cl, bl
        ret
    

puts: ; void puts(char*)
    mov bp, ax
    
    puts_loop:
        mov al, byte [bp]
        cmp al, 0
        je end_puts
        call putc
        inc bp
        jmp puts_loop

    end_puts:
    ret

NEWLINE db 0x0d, 0x0a, 0
newline: ; void newline()
    mov ax, NEWLINE
    jmp puts

getsn: ; short getsn(char*, short)
    mov bp, ax
    mov cx, ax
    add cx, dx
    dec cx
    ; WARN: to optimize this, note that getc doesn't clobber cx either
    getsn_loop:
        call getc
        mov byte [bp], al
        cmp al, 0x0d ; CR (serial sends CRLF)
        je end_getsn
        inc bp
        cmp bp, cx
        jne getsn_loop
    end_getsn:
    mov byte [bp], 0
    ret

getc: ; char getc()
    mov dx, 0x3fd
    in al, dx
    bt ax, 0
    jnc getc ; check readiness
    sub dl, 5
    in al, dx
    cmp al, 0x0a ; ignore lf
    je getc
    ; fall through to putc to echo

putc: ; void putc(char)
    mov dx, 0x3f8
    out dx, al
    ret

; Boot sector magic number
times 510-($-$$) db 0
dw 0xaa55

; flag
db "flag{smashing_the_stAAAAAAAAAAAAAAAck_for_fun_and_profit}"

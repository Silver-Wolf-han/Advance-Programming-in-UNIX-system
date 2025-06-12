
global time
time:
    mov rax, 201
    syscall
    ret

global srand
srand:
    mov rax, rdi
    sub rax, 1
    mov [rel seed], rax
    ret

global grand
grand:
    mov rax, [rel seed]
    ret

global rand
rand:
    mov rax, [rel seed]
    mov rcx, 6364136223846793005
    mul rcx
    add rax, 1
    mov [rel seed], rax
    shr rax, 33
    ret

global sigemptyset
sigemptyset:
    mov qword [rdi], 0
    xor eax, eax
    ret

global sigfillset
sigfillset:
    mov qword [rdi], -1
    xor eax, eax
    ret

global sigaddset
sigaddset:
    cmp esi, 1
    jl .invalid
    cmp esi, 32
    jg .invalid
    mov ecx, esi
    dec ecx         ; set [dex--]
    mov rax, 1
    shl rax, cl     ; shift
    or [rdi], rax
    xor eax, eax
    ret
.invalid:
    mov eax, -1
    ret

global sigdelset
sigdelset:
    cmp esi, 1
    jl .invalid
    cmp esi, 32
    jg .invalid
    mov ecx, esi
    dec ecx
    mov rax, 1
    shl rax, cl
    not rax         ; reverse
    and [rdi], rax  ; and to dele 0 bit
    xor eax, eax
    ret
.invalid:
    mov eax, -1
    ret

global sigismember
sigismember:
    cmp esi, 1
    jl .invalid
    cmp esi, 32
    jg .invalid
    mov rax, [rdi]       ; Load the 64-bit mask
    mov ecx, esi
    dec ecx              ; []
    bt rax, rcx          ; 
    setc al              ;
    movzx eax, al        ;
    ret
.invalid:
    mov eax, -1
    ret

global sigprocmask
sigprocmask:
    mov rax, 14
    mov r10, 8
    syscall
    ret

global setjmp
setjmp:
    mov [rdi + 0], rbx
    mov [rdi + 8], rbp
    mov [rdi + 16], rsp
    mov [rdi + 24], r12
    mov [rdi + 32], r13
    mov [rdi + 40], r14
    mov [rdi + 48], r15

    mov rax, [rsp]
    mov [rdi + 56], rax

    mov rax, 14
    mov rsi, 0
    lea rdx, [rdi + 64]
    mov rdi, 0
    mov r10, 8
    syscall

    xor eax, eax
    ret

global longjmp
longjmp:
    mov [rel val], rsi
    mov rbx, [rdi + 0]
    mov rbp, [rdi + 8]
    mov rsp, [rdi + 16]
    mov r12, [rdi + 24]
    mov r13, [rdi + 32]
    mov r14, [rdi + 40]
    mov r15, [rdi + 48]
    mov rbx, [rdi + 56]

    mov rdx, 0
    lea rsi, [rdi + 64]
    mov rdi, 2
    mov rax, 14
    mov r10, 8
    syscall

    mov rax, [rel val]
    test rax, rax
    jne .retjmp
    mov rax, 1

.retjmp:
    jmp rbx

section .data
    seed dq 0
    val:    resq 1



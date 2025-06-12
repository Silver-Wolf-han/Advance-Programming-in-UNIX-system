
section .bss
align 8
seed:   resq 1              ; reserve 8 bytes
val:    resq 1              ; 第七題用

global time
section .text
time:
    mov rax, 201
    syscall
    ret

global srand
srand:
    mov eax, edi                            ; s
    sub eax, 1                              ; s - 1
    mov [rel seed], rax                     ; <-- 使用 RIP-relative
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

global grand
grand:
    mov rax, [rel seed]     ; 將 seed 載入 rax（回傳值）
    ret

global sigemptyset
sigemptyset:
    mov qword [rdi], 0
    ret

global sigfillset
sigfillset:
    mov qword [rdi], 0xFFFFFFFF
    ret

global sigaddset
sigaddset:
    mov rax, 1
    mov cl, sil
    sub cl, 1
    shl rax, cl
    or  [rdi], rax
    ret

global sigdelset
sigdelset:
    mov rax, 1
    mov cl, sil
    sub cl, 1
    shl rax, cl
    not eax
    and [rdi], rax
    ret

global sigismember
sigismember:
    ;mov qword [rdi], 12
    ;ret
    mov rax, 1
    mov cl, sil
    sub cl, 1
    shl rax, cl
    mov rbx, [rdi]
    and rax, rbx
    setnz al
    movzx ebx, al
    ret

global sigprocmask
sigprocmask:
    ; 參數: rdi = how, rsi = newset, rdx = oldset
    mov rax, 14            ; syscall number for rt_sigprocmask
    mov r10, 8             ; sizeof(sigset_t) = 8 bytes
    syscall                ; 呼叫內核
    ;mov qword [rdx], 0x35
    ret

global setjmp
setjmp:
    ; rdi = env
    mov [rdi + 0], rbx
    mov [rdi + 8], rbp
    mov [rdi + 16], rsp
    mov [rdi + 24], r12
    mov [rdi + 32], r13
    mov [rdi + 40], r14
    mov [rdi + 48], r15

    ; 取得 return address (從 stack 拿)
    mov rax, [rsp]             ; return address 存到 rax
    mov [rdi + 56], rax        ; 存進 env->reg[7]

    ; 存 signal mask：oldset = &env->mask
    mov rax, 14                ; syscall: rt_sigprocmask
    mov rsi, 0                 ; newset = NULL
    lea rdx, [rdi + 64]        ; oldset = &env->mask
    mov rdi, 0                 ; how = SIG_BLOCK
    mov r10, 8                 ; sigset_t 大小
    syscall

    xor eax, eax               ; 第一次 setjmp() 回傳 0
    ret

global longjmp
longjmp:
    mov [rel val], rsi
    ; rdi = env, rsi = val
    mov rbx, [rdi + 0]
    mov rbp, [rdi + 8]
    mov rsp, [rdi + 16]
    mov r12, [rdi + 24]
    mov r13, [rdi + 32]
    mov r14, [rdi + 40]
    mov r15, [rdi + 48]
    mov rbx, [rdi + 56]        ; return address

    ; 還原 signal mask：newset = &env->mask
    mov rdx, 0                 ; oldset = NULL
    lea rsi, [rdi + 64]        ; newset = &env->mask
    mov rdi, 2                 ; how = SIG_SETMASK
    mov rax, 14                ; syscall: rt_sigprocmask
    mov r10, 8
    syscall

    ; 設定 return value：若 val 為 0，改成 1
    mov rax, [rel val]
    test rax, rax
    jne .retjmp
    mov rax, 1

.retjmp:
    jmp rbx                    ; 跳回 setjmp 儲存的 return address

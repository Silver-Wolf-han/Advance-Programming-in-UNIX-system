#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <sys/mman.h>   // mmap(), munmap()

const size_t SIZE = 4096, NOP_END_IDX = 512;
unsigned char *addr;

unsigned char trampoline_code[] = {
    
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,       // mov rdi, 1
    0x48, 0x8d, 0x35, 0x0a, 0x00, 0x00, 0x00,       // lea rsi, [rip+0x0a] ; offset to string
    0x48, 0xc7, 0xc2, 0x17, 0x00, 0x00, 0x00,       // mov rdx, 23
    
    0x0f, 0x05,                                     // syscall
    0xc3,                                           // ret
    
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72, // "Hello from trampoline!\n"
    0x6f, 0x6d, 0x20, 0x74, 0x72, 0x61, 0x6d, 0x70,
    0x6f, 0x6c, 0x69, 0x6e, 0x65, 0x21, 0x0a        // 23 bytes
    
};

void lib_constructor(void) __attribute__((constructor));
void lib_destructor(void) __attribute__((destructor));

void lib_constructor(void) {
    if ((addr = (unsigned char*)mmap((void *)0x0, SIZE, PROT_WRITE | PROT_EXEC, 
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)) == MAP_FAILED) {
        perror("mmap failed\n");
        exit(1);
    }
    
    memset(addr, 0x90, NOP_END_IDX);

    memcpy((unsigned char*)addr + NOP_END_IDX, trampoline_code, sizeof(trampoline_code));
}

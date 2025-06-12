#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <sys/mman.h>   // mmap(), munmap()
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <capstone/capstone.h> // disassemble
#include <inttypes.h>          // disassemble

#define SIZE 4096
#define NOP_END_IDX 512
#define MAX_CODE_SEGMENT_SIZE 10
#define TRAMPOLINE_SIZE 3584
#define MAX_SYS_SIZE 4096

unsigned char* addr;

int64_t handler(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

void trampoline() {
    asm volatile(
        // Write assembly to prepare arguments here

        " mov %r10, %rcx \t\n"
        " push %rsp      \t\n"
        " push (%rsp)      \t\n"
        " andq $-16, %rsp \t\n"

        " push %rax      \t\n"
        " push %rax      \t\n"
        
        " call handler   \t\n"
        " add $16, %rsp   \t\n"
        " movq 8(%rsp), %rsp \t\n"
    );
}


int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8, int64_t r9, int64_t rax) {
    //      Leet	0	1	2	3	4	5	6	7
    // Character	o	i	z	e	a	s	g	t
    if (rax == 1) {
        for (int64_t i = 0; i < rdx; ++i) {
            if (((uint8_t *) rsi)[i] == (uint64_t)'0') {
                ((uint8_t *) rsi)[i] = (uint64_t)'o';
            } else if (((uint8_t *) rsi)[i] == (uint64_t)'1') {
                ((uint8_t *) rsi)[i] = (uint64_t)'i';
            } else if (((uint8_t *) rsi)[i] == (uint64_t)'2') {
                ((uint8_t *) rsi)[i] = (uint64_t)'z';
            } else if (((uint8_t *) rsi)[i] == (uint64_t)'3') {
                ((uint8_t *) rsi)[i] = (uint64_t)'e';
            } else if (((uint8_t *) rsi)[i] == (uint64_t)'4') {
                ((uint8_t *) rsi)[i] = (uint64_t)'a';
            } else if (((uint8_t *) rsi)[i] == (uint64_t)'5') {
                ((uint8_t *) rsi)[i] = (uint64_t)'s';
            } else if (((uint8_t *) rsi)[i] == (uint64_t)'6') {
                ((uint8_t *) rsi)[i] = (uint64_t)'g';
            } else if (((uint8_t *) rsi)[i] == (uint64_t)'7') {
                ((uint8_t *) rsi)[i] = (uint64_t)'t';
            }
        }
    }

    return trigger_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
}

void __raw_asm() {
    asm volatile(
        "trigger_syscall: \t\n"
        // Write assembly to prepare arguments here
        "  mov 8(%rsp), %rax\t\n"
        "  mov %rcx,  %r10\t\n"
        "  syscall \t\n"
        "  ret \t\n"
    );
}

size_t SYS_SIZE = 0;
int64_t rewrite_addr[MAX_SYS_SIZE];

void disassemble_and_rewrite(unsigned long start, unsigned long end) {
    if ((mprotect((char *)start, end - start, PROT_WRITE | PROT_READ | PROT_EXEC)) == -1) {
        perror("mprottect error\n");
        exit(1);
    }
    
    static csh handle = 0;
    
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		perror("cs_open error\n");
        exit(1);
    }

    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn *insn;
	size_t count;

    
	count = cs_disasm(handle, (uint8_t *)start, end - start, start, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
            if (!strncmp(insn[j].mnemonic, "syscall", 7) ) {
                uint8_t *ptr_prev = (uint8_t *)insn[j-2].address;
                uint8_t *ptr = (uint8_t *)insn[j].address;
                if ((uintptr_t) ptr_prev == (uintptr_t) trigger_syscall) {
                    break;
                }
                
                rewrite_addr[SYS_SIZE++] = (int64_t)ptr;
            }
			
		}

		cs_free(insn, count);
	} else {
        perror("ERROR: Failed to disassemble given code!\n");
        exit(1);
    }
    
	cs_close(&handle);
    
}

void rewrite_code() {
	
    FILE *fp;
	if ((fp = fopen("/proc/self/maps", "r")) == NULL) {
        perror("open file error");
        exit(1);
    }

    char buf[SIZE];
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        
        if (strstr(buf, "xp") && !strstr(buf, "[vdso]") && !strstr(buf, "[vsyscall]")) {
            unsigned long start, end;
            if (sscanf(buf, "%lx-%lx", &start, &end) == 2) {
                disassemble_and_rewrite(start, end);
            }
        }
        
    }
	fclose(fp);
}

void lib_constructor(void) __attribute__((constructor));
void lib_destructor(void) __attribute__((destructor));

void lib_constructor(void) {

    if (getenv("ZDEBUG")) {
        asm("int3");
    }

    if ((addr = (unsigned char*)mmap((void *)0x0, SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, 
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)) == MAP_FAILED) {
        perror("mmap failed\n");
        exit(1);
    }

    memset(addr, 0x90, NOP_END_IDX);

    unsigned char trampoline_code[] = {
        0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs [64-bit addr (8-byte)],%r11
        0x41, 0xff, 0xe3,                                               // jmp    *%r11
    };

    size_t start = 0x2;
    ((uint8_t *) trampoline_code)[start + 0] = ((uint64_t) trampoline >> (8 * 0)) & 0xff;
	((uint8_t *) trampoline_code)[start + 1] = ((uint64_t) trampoline >> (8 * 1)) & 0xff;
	((uint8_t *) trampoline_code)[start + 2] = ((uint64_t) trampoline >> (8 * 2)) & 0xff;
	((uint8_t *) trampoline_code)[start + 3] = ((uint64_t) trampoline >> (8 * 3)) & 0xff;
	((uint8_t *) trampoline_code)[start + 4] = ((uint64_t) trampoline >> (8 * 4)) & 0xff;
	((uint8_t *) trampoline_code)[start + 5] = ((uint64_t) trampoline >> (8 * 5)) & 0xff;
	((uint8_t *) trampoline_code)[start + 6] = ((uint64_t) trampoline >> (8 * 6)) & 0xff;
	((uint8_t *) trampoline_code)[start + 7] = ((uint64_t) trampoline >> (8 * 7)) & 0xff;

    memcpy((unsigned char*)addr + NOP_END_IDX, trampoline_code, sizeof(trampoline_code));
    
    rewrite_code();
    
    for (size_t i = 0; i < SYS_SIZE; ++i) {
        uint8_t *ptr = (uint8_t *)rewrite_addr[i];
        ptr[0] = 0xff;
        ptr[1] = 0xd0;
    }
    
}

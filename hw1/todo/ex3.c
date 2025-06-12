#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <sys/mman.h>   // mmap()
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <capstone/capstone.h> // disassemble
#include <inttypes.h>          // disassemble

#include <linux/sched.h>    /* Definition of struct clone_args */
#include <sched.h>          /* Definition of CLONE_* constants */
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <unistd.h>

#define SIZE 4096
#define NOP_END_IDX 512
#define MAX_SYS_SIZE 4096

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

int64_t handler(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern int64_t asm_start(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

unsigned char* addr;
void (*__hook_init_fp)(const syscall_hook_fn_t trigger_syscall, syscall_hook_fn_t *hooked_syscall) = NULL;
static syscall_hook_fn_t hooked_syscall_fn = trigger_syscall;

static uint64_t retptr;

void trampoline() {
    asm volatile(
        // Write assembly to prepare arguments here

        // workaround from TA for vfork
        " cmp $0x3a, %rax    \t\n"
        " jne asm_start      \t\n"
        " pop %rsi           \t\n"
        " pop %rsi           \t\n"
        " syscall            \t\n"
        " push %rsi          \t\n"
        " ret                \t\n"

        " asm_start:         \t\n"
        " mov %r10, %rcx     \t\n"
        
        " push 8(%rsp)       \t\n"
        " pop retptr(%rip)   \t\n"
        
        " push %rsp          \t\n"
        " push (%rsp)        \t\n"
        " andq $-16, %rsp    \t\n"

        " push %r10          \t\n"
        " push %r9           \t\n"
        " push %r8           \t\n"
        " push %rdx          \t\n"
        " push %rsi          \t\n"
        " push %rdi          \t\n"

        " push %rax          \t\n"
        " push %rax          \t\n"
        
        " call handler       \t\n"

        " add $16, %rsp      \t\n"

        " pop %rdi           \t\n"
        " pop %rsi           \t\n"
        " pop %rdx           \t\n"
        " pop %r8            \t\n"
        " pop %r9            \t\n"
        " pop %r10           \t\n"

        " movq 8(%rsp), %rsp \t\n"
        
    );
}


int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8, int64_t r9, int64_t rax) {

    if (rax == 435 /* __NR_clone3 */) {
	 	uint64_t *ca = (uint64_t *) rdi; /* struct clone_args */
	 	if (ca[0] /* flags */ & CLONE_VM) {
			ca[6] /* stack_size */ -= sizeof(uint64_t);
	 		*((uint64_t *) (ca[5] /* stack */ + ca[6] /* stack_size */)) = retptr;
	 	}
	}

	if (rax == __NR_clone || rax == 56) {
		if (rdi & CLONE_VM) { // pthread creation
			/* push return address to the stack */
			rsi -= sizeof(uint64_t);
			*((uint64_t *) rsi) = retptr;
		}
	}


    return hooked_syscall_fn(rdi, rsi, rdx, r10, r8, r9, rax);
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
                uint8_t *ptr_prev = (uint8_t *)insn[j-3].address;
                uint8_t *ptr = (uint8_t *)insn[j].address;
                uint8_t *ptr_next = (uint8_t *)insn[j+3].address;
                if ((uintptr_t) ptr_prev == (uintptr_t) trigger_syscall || 
                    (uintptr_t) ptr_next == (uintptr_t) asm_start) {
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
        if (strstr(buf, "xp") && !strstr(buf, "[vdso]")) {
            unsigned long start, end;
            if (sscanf(buf, "%lx-%lx", &start, &end) == 2) {
                if (start < 0xffffffffff600000) {
                    disassemble_and_rewrite(start, end);
                }
            }
        }
        
    }
	fclose(fp);
}


void lib_constructor(void) __attribute__((constructor));
void lib_constructor(void) {

    if (getenv("ZDEBUG")) {
        asm("int3");
    }

    char* hook_lib_name = getenv("LIBZPHOOK");
    if (!hook_lib_name) {
        perror("Environment variable LIBZPHOOK not found\n");
        exit(1);
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

    void* hook_lib_handle = dlmopen(LM_ID_NEWLM, hook_lib_name, RTLD_LAZY);
    if (!hook_lib_handle) {
        perror("Failed to load library hook_lib_handle\n");
        exit(1);
    }

    __hook_init_fp = dlsym(hook_lib_handle, "__hook_init");
    if (__hook_init_fp == NULL) {
        perror("Can not find __hook_init function\n");
        exit(1);
    }

    __hook_init_fp(trigger_syscall, &hooked_syscall_fn);

}

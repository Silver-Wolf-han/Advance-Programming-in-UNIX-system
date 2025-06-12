#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
static syscall_hook_fn_t original_syscall = NULL;

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8, int64_t r9, int64_t rax) {
    if (rax == 59) {
        fprintf(stderr, "[logger] execve(\"%s\", 0x%lx, 0x%lx)\n", (char *)rdi, rsi, rdx);
    }
    int64_t return_value = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    
    switch (rax) {
        case 257:
            fprintf(stderr, "[logger] openat(");

            if (rdi == -100 || rdi == 4294967196)
                fprintf(stderr, "AT_FDCWD");
            else
                fprintf(stderr, "%ld", rdi);

            fprintf(stderr, ", \"%s\", 0x%lx, %#lo) = %ld\n", (char *)rsi, rdx, r10, return_value);

            break;
        case 0: case 1:
            char function_name[10];
            
            if (rax == 0)
                strcpy(function_name, "read");
            else
                strcpy(function_name, "write");

            fprintf(stderr, "[logger] %s(%ld, \"", function_name, rdi);

            for (size_t i = 0; i < return_value && i < 32; ++i) {
                char* ptr = (char*)(rsi + i);
                if (isprint(ptr[0])) {
                    fprintf(stderr, "%c", ptr[0]);
                } else {
                    switch (ptr[0]) {
                        case '\t':
                            fprintf(stderr, "\\t");
                            break;
                        case '\n':
                            fprintf(stderr, "\\n");
                            break;
                        case '\r':
                            fprintf(stderr, "\\r");
                            break;
                        default:
                            fprintf(stderr, "\\x%02x", (u_int8_t)(ptr[0]));
                            break;
                    }
                }
            }
            fprintf(stderr, "\"");

            if (return_value >= 32)
                fprintf(stderr, "...");

            fprintf(stderr, ", %ld) = %ld\n", rdx, return_value);
            break;
        case 42:
            fprintf(stderr, "[logger] connect(%ld, \"", rdi);
            struct sockaddr *uservaddr = (struct sockaddr *)rsi;
            char IPAddress[50];
            switch(uservaddr->sa_family) {
                case AF_INET:
                    struct sockaddr_in* ip4 = (struct sockaddr_in*)uservaddr;
                    int port = ntohs(ip4->sin_port);
                    inet_ntop(AF_INET, &(ip4->sin_addr), IPAddress, INET_ADDRSTRLEN);
                    fprintf(stderr, "%s:%d", IPAddress, port);
                    break;
                case AF_INET6:
                    struct sockaddr_in6* ip6 = (struct sockaddr_in6*)uservaddr;
                    inet_ntop(AF_INET6, &(ip6->sin6_addr), IPAddress, INET6_ADDRSTRLEN);
                    fprintf(stderr, "%s", IPAddress);
                    break;
                default:
                    fprintf(stderr, "%s:%s", "UNIX", uservaddr->sa_data);
                    break;
            }

            fprintf(stderr, "\", %ld) = %ld\n", rdx, return_value);
            break;
        default:
            break;
    }
    
    return return_value;
}

void __hook_init(const syscall_hook_fn_t trigger_syscall, syscall_hook_fn_t *hooked_syscall) {
    original_syscall = trigger_syscall;
    *hooked_syscall = syscall_hook_fn;
}

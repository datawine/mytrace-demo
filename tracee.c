//
// Created by shenjx on 2020/11/12.
//

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

void
sigusr1_handler() {
    printf("resume from sigusr1\n");
}

int
main() {
    signal(SIGUSR1, sigusr1_handler);
    pause();

    int fd, i;
    void *ptr_dest, *ptr_src;
    fd = open("./test_dest.txt", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
    char buf[4096];
    memset(buf, 0, sizeof(buf));
    for (i = 0; i < 1024; i ++)
        write(fd, buf, sizeof(buf));
    ptr_dest = mmap((void *)140733193388032, 4096 * 1024, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    void *lib_handler = dlopen("./libfuncs.so", RTLD_NOW | RTLD_GLOBAL);
    if (!lib_handler) {
        printf("Dlopen error: %s\n", dlerror());
        exit(0);
    }
    printf("lib_handler %lu\n", (uint64_t)lib_handler);

    int in_msg, out_msg;
    void (*func_exec)(int *in_msg, int *out_msg);
    func_exec = dlsym(lib_handler, "lambda");
    printf("func_exec: %lu(%lx)\n", (uint64_t)func_exec, (uint64_t)func_exec);
    in_msg = 204;
    (*func_exec)(&in_msg, &out_msg);
    printf("out_msg: %d\n", out_msg);

//    pause();
    return 0;
}
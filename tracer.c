//
// Created by shenjx on 2020/11/12.
//

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <unistd.h>
#include <fcntl.h>
#include <syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>

#if __WORDSIZE == 64
# define REG(reg) reg.orig_rax
#else
# define REG(reg) reg.orig_eax
#endif

struct mmap_info {
    unsigned long start_addr;
    unsigned long offset;
};

static unsigned long u_arg[6]; // max args is 6
static void
set_uarg(struct user_regs_struct regs) {
    u_arg[0] = regs.rdi;
    u_arg[1] = regs.rsi;
    u_arg[2] = regs.rdx;
    u_arg[3] = regs.r10;
    u_arg[4] = regs.r8;
    u_arg[5] = regs.r9;
}

static void
print_mmap(struct user_regs_struct regs) {
    set_uarg(regs);

    const unsigned long addr = u_arg[0];
    const unsigned long len = u_arg[1];
    const unsigned long prot = u_arg[2];
    const unsigned long flags = u_arg[3];
    const int fd = u_arg[4];
    unsigned long offset = u_arg[5];

    printf("addr: %lx, len: %lu, prot: %lx, flags: %lx, fd: %d, offset: %lu\n",
           addr, len, prot, flags, fd, offset);
}

static int
get_flag(void) {
    int flag = 0;
    FILE *tmpfp = fopen("/home/ubuntu/projects/python-import/flag.txt", "r");
    fscanf(tmpfp, "%d", &flag);
    fclose(tmpfp);
    return flag;
}

int
main(int argc, char *argv[]) {
    int pid = atoi(argv[1]);
    int status;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
        perror("ptrace attach");
    }
    if (wait(&status) == -1) {
        perror("wait()");
    }
    if (!WIFSTOPPED(status)) {
        printf("for some reason the target did not stop\n");
        return -1;
    }
    if (ptrace(PTRACE_SYSCALL, pid, NULL, SIGUSR1) < 0) {
        perror("ptrace syscall");
    }

    int is_insyscall = 1;
    long long last_file = 0, last_real = 0;
    while (1) {
        if (wait(&status) == -1) {
            perror("wait()");
        }
        if (WIFEXITED(status)) {
            printf("tracee exited\n");
            break;
        }
        if (!WIFSTOPPED(status)) {
            printf("for some reason the target did not stop\n");
            break;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
            perror("get regs");
            break;
        }
        if (REG(regs) == SYS_mmap) {
            set_uarg(regs);
            if (is_insyscall)
                print_mmap(regs);
            if (is_insyscall) {
                if (get_flag() == 1 && u_arg[0] != 140733193388032) {
                    printf(">>>>>>>>>>>>>>>>hijack entering\nstart %lx len %lu\n", u_arg[0], u_arg[1]);
                    if (u_arg[0] == 0) {
                        printf("left unchanged\n");
                    } else {
                        u_arg[0] = u_arg[0] - last_file + last_real;
                        if (ptrace(PTRACE_POKEUSER, pid, 8 * 14, u_arg[0])) {
                            printf("set value error\n");
                        } else {
                            printf("modified to %lu\n", u_arg[0]);
                        }
                    }
                }
            } else {
                if (get_flag() == 1 && u_arg[0] != 140733193388032) {
                    printf(">>>>>>>>>>>>>>>>hijack exiting\norigin result= %llx\n", regs.rax);
                    printf("start %lx len %lu\n", u_arg[0], u_arg[1]);
                    assert(u_arg[1] % 8 == 0);

                    unsigned long file_addr;
                    if (u_arg[0] == 0) {
//                        file_addr = 140733193388032;
                        int rdinfo_fd, wrinfo_fd;
                        struct stat buffer;
                        struct mmap_info minfo;
                        const char *infofn = "/home/ubuntu/projects/python-import/module_mmapinfo.txt";

                        if (stat(infofn, &buffer) == 0) { // minfo exist, read from it
                            if ((rdinfo_fd = open(infofn, O_RDONLY)) < 0) {
                                perror("open read info error");
                                exit(1);
                            }
                            if (read(rdinfo_fd, (void *) &minfo, sizeof(struct mmap_info)) <
                                (int) sizeof(struct mmap_info)) {
                                perror("read info error");
                                exit(1);
                            }
                            close(rdinfo_fd);
                        }
                        unsigned long align_pedding = 0;
                        while (((minfo.start_addr + minfo.offset + align_pedding) % 4096) != 0)
                            align_pedding++;
                        file_addr = minfo.start_addr + minfo.offset + align_pedding;
                        minfo.offset += u_arg[1] + align_pedding;

                        if ((wrinfo_fd = open(infofn, O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
                            perror("open write info error");
                            exit(1);
                        }
                        if (write(wrinfo_fd, (void *) &minfo, sizeof(struct mmap_info)) <
                            (int) sizeof(struct mmap_info)) {
                            perror("write info error");
                            exit(1);
                        }
                    } else {
                        file_addr = regs.rax - last_real + last_file;
                    }
                    last_file = file_addr;
                    last_real = regs.rax;

                    unsigned long i;
                    for (i = 0; i < u_arg[1] / 8; i++) {
                        long data = ptrace(PTRACE_PEEKDATA, (pid_t) pid, (void *) (regs.rax + 8 * i), NULL);
                        ptrace(PTRACE_POKEDATA, (pid_t) pid, (void *) (file_addr + 8 * i), (void *) data);
                    }

                    regs.rax = file_addr;
                    if (ptrace(PTRACE_POKEUSER, pid, 8 * 10, regs.rax)) {
                        printf("set value error\n");
                    }
                    printf("modified %llx to %llx\n", last_real, last_file);
                }
            }
        }
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
            perror("ptrace syscall loop");
            break;
        }
        is_insyscall ^= 1;
    }

    return 0;
}
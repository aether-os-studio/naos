#pragma once

#include <libsyscall.h>
#include <fcntl.h>

int open(const char *name, int mode, int flags);
int close(int fd);
int mkfile(const char *name);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, void *buf, size_t count);
off_t lseek(int fd, off_t offset, int whence);

int waitpid(int pid, int *status);
int getcwd(char *cwd);
int chdir(char *cwd);
int fork();
int execve(const char *name, char **argv, char **envp);
int getdents(int fd, dirent_t *dents, int max);
int kill(int pid);

int getpid();
int getppid();
void usleep(int ms);
uint64_t nanotime();

bool have_proc(int pid);

void srand(unsigned long seed);
int rand(void);

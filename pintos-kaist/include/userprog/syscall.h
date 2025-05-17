#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdint.h>
#include "lib/syscall-nr.h"    // enum 기반 syscall 번호

typedef int pid_t;

void syscall_init (void);
bool is_valid_user_ptr(const void *uaddr);
void check_address(const void *addr);
static void check_buffer_readable(const void *buffer, unsigned size);

static inline int get_user(const uint8_t *uaddr);
static inline bool put_user(uint8_t *udst, uint8_t byte);

void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
int write(int fd, const void *buffer, unsigned size);


// TODO: inline 함수는 구현은 syscall.c에 실제로 넣는 게 좋음 (헤더는 선언만)
#endif /* userprog/syscall.h */

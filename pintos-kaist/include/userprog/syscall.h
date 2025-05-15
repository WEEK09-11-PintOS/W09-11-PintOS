#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define SYS_HALT 0
#define SYS_EXIT 1
#define SYS_EXEC 2
#define SYS_WAIT 3

void syscall_init (void);

bool is_valid_user_ptr(const void *uaddr);
void check_address(const void *addr);

static inline int get_user(const uint8_t *uaddr);
static inline bool put_user(uint8_t *udst, uint8_t byte);

void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);

#endif /* userprog/syscall.h */

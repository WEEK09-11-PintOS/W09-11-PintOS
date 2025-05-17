#include "userprog/syscall.h"
#include <stdio.h>
#warning "USING syscall-nr.h from here"
#include "../include/lib/syscall-nr.h"

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/init.h"     // power_off
#include "userprog/gdt.h"
#include "userprog/process.h" // process_exec, process_wait
#include "threads/flags.h"
#include "intrinsic.h"
#include "string.h"           // strlcpy
#include "threads/vaddr.h"    // is_user_vaddr

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

// System call entry setup
#define MSR_STAR 0xc0000081
#define MSR_LSTAR 0xc0000082
#define MSR_SYSCALL_MASK 0xc0000084

void syscall_init(void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
						((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

// Syscall dispatcher
void syscall_handler(struct intr_frame *f) {
	uint64_t syscall_num = f->R.rax;

	switch (syscall_num) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_EXEC:
		f->R.rax = exec((const char *)f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, (const void *)f->R.rsi, f->R.rdx);
		break;
	default:
		thread_exit(); // Unknown syscall
	}
}

/* 유저 포인터 유효성 검사 */
void check_address(const void *addr) {
	if (addr == NULL || !is_user_vaddr(addr) || get_user(addr) == -1) {
		exit(-1);
	}
}

/* Reads a byte at user virtual address UADDR safely.
   Returns the byte value if successful, -1 if segfault occurred. */
static int get_user(const uint8_t *uaddr) {
    int result;
    asm volatile (
        "mov $-1, %0\n\t"
        "movzbq (%1), %0\n\t"
        : "=&r" (result)
        : "r" (uaddr)
        : "memory"
    );
    return result;
}



// NOTE: 유저 주소에 write 해야 할 syscall (예: read()) 구현 시,
// 커널 보호를 위해 put_user() 필요함. 현재는 사용 X.
/*
static bool put_user(uint8_t *udst, uint8_t byte) {
    int error;
    asm volatile (
        "movl $0, %0\n"
        "movb %b2, (%1)\n"
        : "=&r"(error)
        : "r"(udst), "q"(byte)
        : "memory"
    );
    return error == 0;
}
*/

/* SYS_HALT: PintOS 종료 */
void halt(void) {
	power_off();
}

/* SYS_EXIT: 현재 쓰레드 종료 및 상태 출력 */
void exit(int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

/* SYS_EXEC: 새로운 프로그램 실행 */
pid_t exec(const char *cmd_line) {
	check_address(cmd_line);

	// null termination 검증
	bool null_found = false;
	for (int i = 0; i < PGSIZE; i++) {
		check_address(cmd_line + i);
		if (cmd_line[i] == '\0') {
			null_found = true;
			break;
		}
	}
	if (!null_found) exit(-1);

	char *cmd_line_copy = palloc_get_page(PAL_USER);
	if (cmd_line_copy == NULL) exit(-1);

	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	if (process_exec(cmd_line_copy) == -1)
		exit(-1);

	NOT_REACHED();
}

/* SYS_WAIT: 자식 프로세스 종료 대기 */
int wait(pid_t pid) {
	return process_wait(pid);
}

/* SYS_WRITE: 표준 출력 (fd == 1)으로 버퍼 출력 */
int write(int fd, const void *buffer, unsigned size) {
	if (fd != 1)
		return -1;

	printf("SYS_WRITE CALLED: size=%u\n", size);  // 로그 출력

	check_buffer_readable(buffer, size);

	putbuf((const char *)buffer, size);
	return size;
}
/* 버퍼 전체 읽기 가능한지 검사 */
static void check_buffer_readable(const void *buffer, unsigned size) {
	const uint8_t *start = buffer;
	const uint8_t *end = start + size;
	while (start < end) {
		check_address(start);
		start = pg_round_down(start) + PGSIZE;
	}
}

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* syscall dispatcher */
void syscall_handler(struct intr_frame *f)
{
	uint64_t syscall_num = f->R.rax;

	switch (syscall_num)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	default:
		thread_exit(); // Unknown syscall
	}
}

bool is_valid_user_ptr(const void *uaddr) {
	// TODO
}
void check_address(const void *addr) {
	// TODO
}

void halt(void) {
	// TODO
	// 핀토스 종료 함수
}

void exit(int status) {
	// TODO
	// 현재 사용자 프로그램을 종료하고 반환하는 함수
}

int exec(const char *cmd_line) {
	// TODO
	// 현재 프로세스를 이름이 cmd_line인 지정된 실행파일로 교체하는 함수
	// cmd_line은 NULL이 아니어야 하며, 유효한 사용자 포인터여야 함
}

int wait(pid_t pid) {
	// TODO
	// 자식 프로세스를 기다림. 
}

pid_t fork (const char *thread_name) {
	// TODO
	// 현재 프로세스를 복제하여 새로운 프로세스를 생성하는 함수
}

int write(int fd, const void *buffer, unsigned size) {
    // TODO: 유저 포인터 유효성 검사
    // TODO: fd == 1인 경우 stdout 처리 (putbuf 사용)
    // TODO: 그 외 fd는 현재 지원하지 않음
    // TODO: 실패 시 -1 반환
}

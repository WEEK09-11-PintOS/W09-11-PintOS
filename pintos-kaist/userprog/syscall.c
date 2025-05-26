#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/validate.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/kernel/console.h"     // 커널 콘솔 입출력 함수 제공 (putbuf, printf 등)
#include "lib/user/syscall.h"       // 유저 프로그램이 사용하는 시스템 콜 번호 및 인터페이스 정의
#include "filesys/directory.h"      // 디렉터리 관련 자료구조 및 함수 (디렉터리 열기, 탐색 등)
#include "filesys/filesys.h"        // 파일 시스템 전반에 대한 함수 및 초기화/포맷 인터페이스
#include "filesys/file.h"           // 개별 파일 객체(file 구조체) 및 파일 입출력 함수 정의 (read, write 등)

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

static void sys_halt();
static tid_t sys_exec(const char *cmd_line);
int sys_wait(int pid);

tid_t sys_fork(const char *thread_name, struct intr_frame *f);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file_name);
static void sys_close(int fd);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
	uint64_t syscall_num = f->R.rax;
	uint64_t arg1 = f->R.rdi;
	uint64_t arg2 = f->R.rsi;
	uint64_t arg3 = f->R.rdx;
	uint64_t arg4 = f->R.r10;
	uint64_t arg5 = f->R.r8;
	uint64_t arg6 = f->R.r9;

	switch (syscall_num)
	{
	case SYS_HALT:
		sys_halt();
		break;
	case SYS_EXIT:
		sys_exit((int)arg1);
		break;
	case SYS_EXEC:
		f->R.rax = sys_exec((const char *)arg1);
		break;
	case SYS_WAIT:
		f->R.rax = sys_wait((int)arg1);
		break;
	case SYS_FORK:
		f->R.rax = sys_fork((const char *)arg1, f);
		break;
	case SYS_CREATE:
		f->R.rax = sys_create((const char *)arg1, (unsigned)arg2);
		break;
	case SYS_REMOVE:
		f->R.rax = sys_remove((const char *)arg1);
		break;
	case SYS_OPEN:
		f->R.rax = sys_open((const char *)arg1);
		break;
    case SYS_CLOSE:
		sys_close((int)arg1);
		break;
	case SYS_FILESIZE:
		f->R.rax = sys_filesize((int)arg1);
		break;
	case SYS_READ:
		f->R.rax = sys_read((int)arg1, (void *)arg2, (unsigned)arg3);
		break;
	case SYS_WRITE:
		f->R.rax = sys_write((int)arg1, (const void *)arg2, (unsigned)arg3);
		break;
	case SYS_SEEK:
		sys_seek((int)arg1, (unsigned)arg2);
		break;
	case SYS_TELL:
		f->R.rax = sys_tell(arg1);
		break;

	default:
		thread_exit();
		break;
	}
}

static void sys_halt() {
	power_off();
}

void sys_exit(int status) {
	struct thread *cur = thread_current();

	cur->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);

	thread_exit();
}

static tid_t sys_exec(const char *cmd_line) {
	validate_str(cmd_line);

	char *cmd_line_copy = palloc_get_page(PAL_ZERO);

	if (cmd_line_copy == NULL) {
		sys_exit(-1);
	}
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	if (process_exec(cmd_line_copy) == -1) {
		sys_exit(-1);
	}
}

int sys_wait(int pid)
{
	return process_wait(pid);
}

tid_t sys_fork(const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

static bool sys_create(const char *file, unsigned initial_size) {
	validate_ptr(file, 1);

	char kernel_buf[NAME_MAX + 1];
	if (!copy_in(kernel_buf, file, sizeof kernel_buf)) {
		return false;
	}

	if (strlen(kernel_buf) == 0) {
		return false;
	}

	struct dir *dir = dir_open_root();
	if (dir == NULL) {
		return false;
	}

	struct inode *inode;
	if (dir_lookup(dir, kernel_buf, &inode)) {
		dir_close(dir);
		return false;
	}

	lock_acquire(&filesys_lock);
	bool success = filesys_create(kernel_buf, initial_size);
	lock_release(&filesys_lock);

	dir_close(dir);

	return success;
}

static bool sys_remove(const char *file) {
	validate_ptr(file, 1);

	if (file == NULL) {
		return false;
	}

	return filesys_remove(file);
}

static int sys_open(const char *file_name) {
	validate_ptr(file_name, 1);

	lock_acquire(&filesys_lock);
	struct file *file = filesys_open(file_name);

	if (file == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	int fd = process_add_file(file);

	if (fd == -1) {
		file_close(file);
	}
	lock_release(&filesys_lock);

	return fd;
}

static void sys_close(int fd) {
	struct file *file = process_get_file(fd);

	if (file == NULL) {
		return;
	}

	file_close(file);
	thread_current()->fdt[fd] = NULL;
}

static int sys_filesize(int fd) {
	struct file *file = process_get_file(fd);

	if (file == NULL) {
		return -1;
	}

	return file_length(file);
}

static int sys_read(int fd, void *buffer, unsigned size) {
	validate_ptr(buffer, size);

	char *ptr = (char *)buffer;
	int bytes_read = 0;

	lock_acquire(&filesys_lock);

	if (fd == STDIN_FILENO) {
		for (int i = 0; i < size; i++) {
			*ptr++ = input_getc();
			bytes_read++;
		}
		lock_release(&filesys_lock);
	} else {
		if (fd < 3) {
			lock_release(&filesys_lock);
			return -1;
		}

		struct file *file = process_get_file(fd);
		if (file == NULL) {
			lock_release(&filesys_lock);
			return -1;
		}

		bytes_read = file_read(file, buffer, size);
		lock_release(&filesys_lock);
	}

	return bytes_read;
}

static int sys_write(int fd, const void *buffer, unsigned size) {
	validate_ptr(buffer, size);

	if (fd == 0 || fd == 2) {
		return -1;
	}

	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}

	struct file *file = process_get_file(fd);
	if (file == NULL) {
		return -1;
	}

	lock_acquire(&filesys_lock);
	int bytes_write = file_write(file, buffer, size);
	lock_release(&filesys_lock);

	if (bytes_write < 0) {
		return -1;
	}

	return bytes_write;
}

static void sys_seek (int fd, unsigned position) {
	struct file *file = process_get_file(fd);

	if (file == NULL) {
		return;
	}

	file_seek(file, position);
}

static unsigned sys_tell (int fd) {
	struct file *file = process_get_file(fd);

	if (file == NULL) {
		return 0;
	}

	return file_tell(file);
}
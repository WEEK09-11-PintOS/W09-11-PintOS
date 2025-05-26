#include "userprog/validate.h"
#include "userprog/syscall.h"     /* syscall_exit() */
#include "threads/thread.h"       /* thread_current(), pml4 */
#include "threads/vaddr.h"        /* PHYS_BASE, pg_ofs */
#include "threads/mmu.h"          /* PGSIZE */
#include "threads/pte.h"          /* pml4_get_page() */
#include <string.h>               /* memcpy */

/* 내부 헬퍼: 단일 가상 주소 uaddr이 
   - NULL이 아니고
   - 사용자 영역에 속하며
   - 현재 프로세스의 페이지 테이블에 매핑되어 있는지 확인 */
static bool
check_page (const void *uaddr) {
    return uaddr != NULL &&
           is_user_vaddr(uaddr) &&
           pml4_get_page (thread_current ()->pml4, uaddr) != NULL;
}

void validate_ptr (const void *uaddr, size_t size) {
    if (size == 0) return;

    const uint8_t *usr = uaddr;
    size_t left = size;

    while (left > 0) {
        if (!check_page(usr)) {
            sys_exit(-1);
        }
        size_t page_left = PGSIZE - pg_ofs(usr);
        size_t chunk = left < page_left ? left : page_left;

        usr += chunk;
        left -= chunk;
    }
}

void validate_str (const char *str) {
    for (const char *p = str;; ++p) {
        validate_ptr(p, 1);
        if (*p == '\0') {
            break;
        }
    }
}

/* 사용자 영역 주소 uaddr에서 단일 바이트를 안전하게 읽기
   → 예외(page fault) 발생 시 -1 반환 */
int64_t get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
        "movabsq $done_get, %0\n"   // 예외 발생 시 점프할 주소를 %0에 저장
        "movzbq %1, %0\n"           // uaddr이 가리키는 1바이트 값을 읽어 zero-extend 후 %0에 저장
        "done_get:\n"               // 예외 발생 시 이곳으로 점프하여 결과 처리
        : "=&a" (result)            // 출력: result에 저장됨 (%rax 사용)
        : "m" (*uaddr));            // 입력: uaddr이 가리키는 메모리 바이트
    return result;
}

/* 사용자 영역 주소 udst에 단일 바이트 byte를 안전하게 쓰기
   → 예외(page fault) 발생 시 false 반환 */
bool put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;  // 예외 발생 여부 확인을 위한 변수

    printf("[put_user] trying to write to %p\n", udst);  // 디버깅용 출력

    __asm __volatile (
        "movabsq $done_put, %0\n"  // 예외 발생 시 복구할 위치 주소를 %0에 저장
        "movb %b2, %1\n"           // byte 값을 udst가 가리키는 주소에 저장 시도 (1바이트)
        "done_put:\n"              // 예외 발생 시 여기로 복귀
        : "=&a" (error_code),      // 출력: %rax에 저장될 복구 주소 → 예외가 없으면 그대로 통과
          "=m" (*udst)             // 출력 메모리 위치: 실제 쓰기 대상
        : "q" (byte));             // 입력: 저장할 바이트 값

    return error_code != -1;       // 예외 발생 시 false, 아니면 true 반환
}

/* 사용자 영역에서 커널 영역으로 size 바이트만큼 메모리를 복사
   → 복사 전 대상 범위를 validate_ptr()로 검증 */
size_t copy_in (void *kernel_dst, const void *user_src, size_t size) {
    validate_ptr (user_src, size);
    memcpy (kernel_dst, user_src, size);
    return size;
}

/* 커널 영역에서 사용자 영역으로 size 바이트만큼 메모리를 복사
   → 복사 전 대상 범위를 validate_ptr()로 검증 */
size_t
copy_out (void *user_dst, const void *kernel_src, size_t size) {
    validate_ptr (user_dst, size);           // 복사 전에 사용자 목적지 포인터 범위 검증
    memcpy (user_dst, kernel_src, size);     // 검증 완료 → 사용자 영역으로 복사 수행
    return size;                             // 실제 복사한 바이트 수 반환
}
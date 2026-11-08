/* SPDX-License-Identifier: BSD-3-Clause
 * Independent CPL3 client for the BasmOS OSIF v1 ABI.  This probe uses the
 * published interrupt contract directly, without the Jash OSIF wrappers.
 */
.section .text
.code32
.global _start
_start:
    cld
    xorl %eax, %eax
    int $0x80
    cmpl $1, %eax
    jne fail_query
    cmpl $15, %edx
    jne fail_query
    cmpl $0x200000, %ecx
    jne fail_query
    movl $query_ok, %esi
    call puts

    movl $2, %eax
    int $0x80
    cmpl $-11, %eax
    jne fail_empty
    movl $empty_ok, %esi
    call puts

    movl $0x13572468, %ebx
    movl $0x2468ace0, %esi
    movl $0x89abcdef, %edi
    movl $0x11223344, %ebp
    movl $0x7fffffff, %eax
    int $0x80
    cmpl $-38, %eax
    jne fail_unknown
    cmpl $0x13572468, %ebx
    jne fail_preserve
    cmpl $0x2468ace0, %esi
    jne fail_preserve
    cmpl $0x89abcdef, %edi
    jne fail_preserve
    cmpl $0x11223344, %ebp
    jne fail_preserve
    movl $-1, %eax
    int $0x80
    cmpl $-38, %eax
    jne fail_unknown
    movl $unknown_ok, %esi
    call puts
    movl $preserve_ok, %esi
    call puts

    movl $write_prefix, %esi
    call puts
    xorl %ebx, %ebx
    call putc
    movl $newline, %esi
    call puts

    movl $3, %eax
    int $0x80
    movl %eax, %edi
wait_tick:
    movl $3, %eax
    int $0x80
    cmpl %edi, %eax
    je wait_tick
    movl $ticks_ok, %esi
    call puts

    movl $need_nul, %esi
    call puts
read_nul:
    movl $2, %eax
    int $0x80
    cmpl $-11, %eax
    je read_nul
    testl %eax, %eax
    jne fail_nul
    movl $nul_ok, %esi
    call puts
    movl $2, %eax
    int $0x80
    cmpl $-11, %eax
    jne fail_after
    movl $after_ok, %esi
    call puts
    movl $done, %esi
    call puts
    movl $7, %ebx
    movl $4, %eax
    int $0x80
unexpected_return:
    jmp unexpected_return

fail_query: movl $fail_query_s, %esi; jmp fail
fail_empty: movl $fail_empty_s, %esi; jmp fail
fail_unknown: movl $fail_unknown_s, %esi; jmp fail
fail_preserve: movl $fail_preserve_s, %esi; jmp fail
fail_nul: movl $fail_nul_s, %esi; jmp fail
fail_after: movl $fail_after_s, %esi; jmp fail
fail:
    call puts
    movl $255, %ebx
    movl $4, %eax
    int $0x80
    jmp unexpected_return

puts:
    lodsb
    testb %al, %al
    jz puts_done
    movzbl %al, %ebx
    call putc
    jmp puts
puts_done:
    ret
putc:
    movl $1, %eax
    int $0x80
    cmpl $-11, %eax
    je putc
    cmpl $1, %eax
    jne unexpected_return
    ret

query_ok: .asciz "QUERY:OK\n"
empty_ok: .asciz "EMPTY:EAGAIN\n"
unknown_ok: .asciz "UNKNOWN:ENOSYS\n"
preserve_ok: .asciz "CALLEE:OK\n"
write_prefix: .asciz "WRITE:"
newline: .asciz "\n"
ticks_ok: .asciz "TICKS:PROGRESS\n"
need_nul: .asciz "NEED-NUL\n"
nul_ok: .asciz "READ:NUL\n"
after_ok: .asciz "AFTER:EAGAIN\n"
done: .asciz "ABI:DONE\n"
fail_query_s: .asciz "FAIL:QUERY\n"
fail_empty_s: .asciz "FAIL:EMPTY\n"
fail_unknown_s: .asciz "FAIL:UNKNOWN\n"
fail_preserve_s: .asciz "FAIL:CALLEE\n"
fail_nul_s: .asciz "FAIL:NUL\n"
fail_after_s: .asciz "FAIL:AFTER\n"
.section .note.GNU-stack,"",@progbits

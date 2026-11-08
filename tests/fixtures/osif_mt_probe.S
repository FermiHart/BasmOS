/* SPDX-License-Identifier: BSD-3-Clause
 * Independent BasmOS ABI 2 client. No Jash code or wrappers are linked.
 * Two CPL3 contexts enter offsets 0 and 4. All privileged work is requested
 * through int 0x21; progress checks deliberately include syscall-free loops.
 */
.section .text
.code32
.global _start, mt_peer_entry, mt_main_context_loop, mt_peer_context_loop
_start:
    jmp main
    .org 4
mt_peer_entry:
    jmp peer

.macro check reg, value
    cmpl $\value, %\reg
    jne fail_context
.endm
.macro pcheck reg, value
    cmpl $\value, %\reg
    jne peer_bad
.endm
.macro segment reg, value, failure
    push %\reg
    cmpw $\value, (%esp)
    leal 4(%esp), %esp
    jne \failure
.endm

main:
    cld
    xorl %eax, %eax
    int $0x21
    cmpl $2, %eax
    jne fail_query
    cmpl $0x3b, %edx
    jne fail_query
    cmpl $0x200000, %ecx
    jne fail_query
    movl $query_ok, %esi
    call puts
    movl $3, %eax
    int $0x21
    cmpl $-38, %eax
    jne fail_unknown
    movl $0xffffffff, %eax
    int $0x21
    cmpl $-38, %eax
    jne fail_unknown

    /* Main and peer intentionally retain different FS/GS/ES and DF. */
    xorl %eax, %eax
    movw %ax, %fs
    movw $0x23, %ax
    movw %ax, %gs
    movl %esp, main_sp
    movl $0x11111111, %eax
    movl $0x22222222, %ebx
    movl $0x33333333, %ecx
    movl $0x44444444, %edx
    movl $0x55555555, %esi
    movl $0x66666666, %edi
    movl $0x77777777, %ebp
    /* Reset only after every sentinel is live. The peer must receive a new
     * timer slice before this loop can finish, even if it ran before main. */
    movl $0, peer_loops
mt_main_context_loop:
    check eax, 0x11111111
    check ebx, 0x22222222
    check ecx, 0x33333333
    check edx, 0x44444444
    check esi, 0x55555555
    check edi, 0x66666666
    check ebp, 0x77777777
    cmpl main_sp, %esp
    jne fail_context
    segment ds, 0x23, fail_context
    segment es, 0x23, fail_context
    segment fs, 0, fail_context
    segment gs, 0x23, fail_context
    pushfl
    testl $0x400, (%esp)
    leal 4(%esp), %esp
    jnz fail_context
    incl main_loops
    cmpl $0, peer_error
    jne fail_context
    cmpl $100000, peer_loops
    jb mt_main_context_loop
    cmpl $100000, main_loops
    jb mt_main_context_loop
    movl $1, phase
    xorl %eax, %eax
    movw %ax, %gs
    movl $context_ok, %esi
    call puts

    /* Returning ABI calls preserve the C callee-saved registers. */
    movl $0x13572468, %ebx
    movl $0x2468ace0, %esi
    movl $0x89abcdef, %edi
    movl $0x11223344, %ebp
    movl $0x7fffffff, %eax
    int $0x21
    cmpl $-38, %eax
    jne fail_unknown
    cmpl $0x13572468, %ebx
    jne fail_callee
    cmpl $0x2468ace0, %esi
    jne fail_callee
    cmpl $0x89abcdef, %edi
    jne fail_callee
    cmpl $0x11223344, %ebp
    jne fail_callee
    movl $callee_ok, %esi
    call puts

    /* Both one-byte channels begin empty. A stored zero is a real byte. */
    xorl %ebx, %ebx
    call recv
    cmpl $-11, %eax
    jne fail_empty
    movl $0x100, %ebx
    call recv
    cmpl $-11, %eax
    jne fail_empty
    xorl %ebx, %ebx
    call send
    cmpl $1, %eax
    jne fail_nul
    movl $42, %ebx
    call send
    cmpl $-11, %eax
    jne fail_full
    xorl %ebx, %ebx
    call recv
    testl %eax, %eax
    jne fail_nul
    call recv
    cmpl $-11, %eax
    jne fail_empty
    movl $nul_ok, %esi
    call puts
    movl $full_ok, %esi
    call puts

    movl $17, %ebx
    call send
    cmpl $1, %eax
    jne fail_channels
    movl $0x122, %ebx
    call send
    cmpl $1, %eax
    jne fail_channels
    xorl %ebx, %ebx
    call recv
    cmpl $17, %eax
    jne fail_channels
    movl $0x100, %ebx
    call recv
    cmpl $34, %eax
    jne fail_channels
    movl $channels_ok, %esi
    call puts

    /* Every byte value on both channels; retry/full must not overwrite. */
    xorl %ebp, %ebp
values_loop:
    movl %ebp, %ebx
    call send
    cmpl $1, %eax
    jne fail_values
    xorl $0xff, %ebx
    call send
    cmpl $-11, %eax
    jne fail_values
    call recv
    movl %ebp, %edx
    andl $255, %edx
    cmpl %edx, %eax
    jne fail_values
    call recv
    cmpl $-11, %eax
    jne fail_values
    incl %ebp
    cmpl $512, %ebp
    jne values_loop
    movl $values_ok, %esi
    call puts

    /* Only BH bit zero selects a channel; other argument bits are bounded. */
    movl $0xffffffff, %ebx
    call send
    cmpl $1, %eax
    jne fail_channel_mask
    movl $0x7fffffff, %ebx
    call recv
    cmpl $255, %eax
    jne fail_channel_mask
    xorl %ebx, %ebx
    call recv
    cmpl $-11, %eax
    jne fail_channel_mask
    movl $mask_ok, %esi
    call puts

    /* Actual inter-context exchange; peer is CPU-bound between IRQ slices. */
    movl $2, phase
    xorl %ebp, %ebp
roundtrip:
    movl %ebp, %ebx
    andl $255, %ebx
send_again:
    call send
    cmpl $-11, %eax
    je send_again
    cmpl $1, %eax
    jne fail_exchange
    movl $0x100, %ebx
recv_again:
    call recv
    cmpl $-11, %eax
    je recv_again
    movl %ebp, %edx
    andl $255, %edx
    cmpl %edx, %eax
    jne fail_exchange
    incl %ebp
    cmpl $512, %ebp
    jne roundtrip
wait_peer_receipt:
    cmpl $512, peer_received
    jne wait_peer_receipt
    movl $3, phase
    movl $exchange_ok, %esi
    call puts

    movl $2, %eax
    int $0x21
    cmpl $-11, %eax
    jne fail_rx
    movl $need_nul, %esi
    call puts
read_nul:
    movl $2, %eax
    int $0x21
    cmpl $-11, %eax
    je read_nul
    testl %eax, %eax
    jne fail_rx
    movl $2, %eax
    int $0x21
    cmpl $-11, %eax
    jne fail_rx
    movl $rx_ok, %esi
    call puts
    movl $write_prefix, %esi
    call puts
    xorl %ebx, %ebx
    call putc
    movl $newline, %esi
    call puts
    movl $done, %esi
    call puts
    movl $7, %ebx
    movl $4, %eax
    int $0x21
unexpected_return:
    jmp unexpected_return

peer:
    movw $0x23, %ax
    movw %ax, %fs
    xorl %eax, %eax
    movw %ax, %es
    movw %ax, %gs
    std
    movl %esp, peer_sp
    movl $0x81818181, %eax
    movl $0x82828282, %ebx
    movl $0x83838383, %ecx
    movl $0x84848484, %edx
    movl $0x85858585, %esi
    movl $0x86868686, %edi
    movl $0x87878787, %ebp
mt_peer_context_loop:
    pcheck eax, 0x81818181
    pcheck ebx, 0x82828282
    pcheck ecx, 0x83838383
    pcheck edx, 0x84848484
    pcheck esi, 0x85858585
    pcheck edi, 0x86868686
    pcheck ebp, 0x87878787
    cmpl peer_sp, %esp
    jne peer_bad
    segment ds, 0x23, peer_bad
    segment es, 0, peer_bad
    segment fs, 0x23, peer_bad
    segment gs, 0, peer_bad
    pushfl
    testl $0x400, (%esp)
    leal 4(%esp), %esp
    jz peer_bad
    incl peer_loops
    cmpl $0, phase
    je mt_peer_context_loop
    cld
    movw $0x23, %ax
    movw %ax, %es
    xorl %eax, %eax
    movw %ax, %fs
peer_wait:
    cmpl $2, phase
    jne peer_wait
    xorl %ebx, %ebx
    call recv
    cmpl $-11, %eax
    je peer_wait
    cmpl $255, %eax
    ja peer_bad
    movl %eax, %ebx
    orl $0x100, %ebx
peer_send_again:
    call send
    cmpl $-11, %eax
    je peer_send_again
    cmpl $1, %eax
    jne peer_bad
    incl peer_received
    jmp peer_wait
peer_bad:
    movl $1, peer_error
    jmp peer_bad

fail_query: movl $fail_query_s, %esi; jmp fail
fail_unknown: movl $fail_unknown_s, %esi; jmp fail
fail_context: movl $fail_context_s, %esi; jmp fail
fail_callee: movl $fail_callee_s, %esi; jmp fail
fail_empty: movl $fail_empty_s, %esi; jmp fail
fail_nul: movl $fail_nul_s, %esi; jmp fail
fail_full: movl $fail_full_s, %esi; jmp fail
fail_channels: movl $fail_channels_s, %esi; jmp fail
fail_values: movl $fail_values_s, %esi; jmp fail
fail_channel_mask: movl $fail_mask_s, %esi; jmp fail
fail_exchange: movl $fail_exchange_s, %esi; jmp fail
fail_rx: movl $fail_rx_s, %esi; jmp fail
fail:
    cld
    movw $0x23, %ax
    movw %ax, %ds
    movw %ax, %es
    call puts
    movl $255, %ebx
    movl $4, %eax
    int $0x21
    jmp unexpected_return

send:
    movl $5, %eax
    int $0x21
    ret
recv:
    movl $6, %eax
    int $0x21
    ret
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
    int $0x21
    cmpl $-11, %eax
    je putc
    cmpl $1, %eax
    jne unexpected_return
    ret

query_ok: .asciz "MT:QUERY\n"
context_ok: .asciz "MT:CONTEXT\n"
callee_ok: .asciz "MT:CALLEE\n"
nul_ok: .asciz "MT:NUL\n"
full_ok: .asciz "MT:FULL\n"
channels_ok: .asciz "MT:CHANNELS\n"
values_ok: .asciz "MT:VALUES512\n"
mask_ok: .asciz "MT:CHANNEL-MASK\n"
exchange_ok: .asciz "MT:ROUNDTRIPS512\n"
need_nul: .asciz "MT:NEED-NUL\n"
rx_ok: .asciz "MT:RX-NUL\n"
write_prefix: .asciz "MT:TX["
newline: .asciz "]\n"
done: .asciz "MT:DONE\n"
fail_query_s: .asciz "FAIL:QUERY\n"
fail_unknown_s: .asciz "FAIL:UNKNOWN\n"
fail_context_s: .asciz "FAIL:CONTEXT\n"
fail_callee_s: .asciz "FAIL:CALLEE\n"
fail_empty_s: .asciz "FAIL:EMPTY\n"
fail_nul_s: .asciz "FAIL:NUL\n"
fail_full_s: .asciz "FAIL:FULL\n"
fail_channels_s: .asciz "FAIL:CHANNELS\n"
fail_values_s: .asciz "FAIL:VALUES\n"
fail_mask_s: .asciz "FAIL:CHANNEL-MASK\n"
fail_exchange_s: .asciz "FAIL:EXCHANGE\n"
fail_rx_s: .asciz "FAIL:RX\n"

.section .data
.global main_loops, peer_loops, peer_error, peer_received
phase: .long 0
main_sp: .long 0
peer_sp: .long 0
main_loops: .long 0
peer_loops: .long 0
peer_error: .long 0
peer_received: .long 0
.section .note.GNU-stack,"",@progbits

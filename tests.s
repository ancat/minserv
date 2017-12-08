%include "minserv.s"
section .data
sample_string_poop:
    db      'poop', 10, 0

sample_string_empty:
    db      '', 0

test_failed:
    db      9, 0x1b, 0x5b, 0x33, 0x31, 0x6d, 'test failed', 0x1b, 0x5b, 0x33, 0x39, 0x6d, 10, 0

test_passed:
    db      9, 0x1b, 0x5b, 0x33, 0x32, 0x6d, 'test passed', 0x1b, 0x5b, 0x33, 0x39, 0x6d, 10, 0

test_name_strlen_poop:
    db      'strlen_poop', 0
test_name_strlen_empty:
    db      'strlen_empty', 0
test_name_strcmp_equal:
    db      'strcmp_equal', 0

seen_failure:
    db      0

final_pass:
    db      0x1b, 0x5b, 0x33, 0x32, 0x6d, 'all tests passed! :)', 0x1b, 0x5b, 0x33, 0x39, 0x6d, 10, 0

final_fail:
    db      0x1b, 0x5b, 0x33, 0x31, 0x6d, 'some tests failed! :(', 0x1b, 0x5b, 0x33, 0x39, 0x6d, 10, 0

global _start
_start:
    call    test_strlen
    call    test_strcmp
    call    print_verdict
    mov     rdi, rax
    mov     rax, 60
    syscall

test_strcmp:
    mov     rdi, sample_string_poop
    mov     rsi, sample_string_poop
    mov     rdx, test_name_strcmp_equal
    call    assert_strings_equal
    ret

test_strlen:
    mov     rdi, sample_string_poop
    call    strlen
    mov     rdi, rax
    mov     rsi, 4
    mov     rdx, test_name_strlen_poop
    call    assert_ints_equal

    mov     rdi, sample_string_empty
    call    strlen
    mov     rdi, rax
    mov     rsi, 0
    mov     rdx, test_name_strlen_empty
    call    assert_ints_equal

    ret

assert_strings_not_equal:
    push    rdi
    push    rsi

    mov     rdi, 0
    mov     rsi, rdx
    call    write_string

    pop     rsi
    pop     rdi

    call    strcmp
    jnz     assert_strings_not_equal_yes
    mov     rsi, test_failed
    call    set_failure
    jmp     assert_strings_not_equal_ret
assert_strings_not_equal_yes:
    mov     rsi, test_passed
assert_strings_not_equal_ret:
    mov     rdi, 0
    call    write_string
    ret

assert_strings_equal:
    push    rdi
    push    rsi

    mov     rdi, 0
    mov     rsi, rdx
    call    write_string

    pop     rsi
    pop     rdi

    call    strcmp
    jz      assert_strings_equal_yes
    mov     rsi, test_failed
    call    set_failure
    jmp     assert_strings_equal_ret
assert_strings_equal_yes:
    mov     rsi, test_passed
assert_strings_equal_ret:
    mov     rdi, 0
    call    write_string
    ret

assert_ints_equal:
    push    rdi
    push    rsi

    mov     rdi, 0
    mov     rsi, rdx
    call    write_string

    pop     rsi
    pop     rdi

    cmp     rdi, rsi
    jz      assert_ints_equal_yes
    mov     rsi, test_failed
    call    set_failure
    jmp     assert_ints_equal_ret
assert_ints_equal_yes:
    mov     rsi, test_passed
assert_ints_equal_ret:
    mov     rdi, 0
    call    write_string
    ret

set_failure:
    push    rdi
    mov     rdi, seen_failure
    mov     byte [rdi], 1
    pop     rdi
    ret

print_verdict:
    push    rdi
    push    rsi
    mov     rdi, seen_failure
    mov     dl, byte [rdi]
    cmp     dl, 0
    jz      print_verdict_success
    mov     rsi, final_fail
    mov     rax, 1
    jmp     print_verdict_ret
print_verdict_success:
    mov     rsi, final_pass
    mov     rax, 0
print_verdict_ret:
    mov     rdi, 0
    push    rax
    call    write_string
    pop     rax
    pop     rsi
    pop     rdi
    ret

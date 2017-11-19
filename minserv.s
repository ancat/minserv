section .data

message:
    db      'HTTP/1.1 200 OK', 13, 10, 'Content-Length: 8', 13, 10, 13, 10, 'DYNAMIC', 10, 0

http_response_404:
    db      'HTTP/1.1 404 File Not Found', 13, 10, 'Content-Length: 4', 13, 10, 13, 10, '404', 10, 0

http_response_200:
    db      'HTTP/1.1 200 OK', 13, 10, 0

http_header_content_length:
    db      'Content-Length: 1024', 13, 10, 0

http_header_content_length_dynamic:
    db      'Content-Length: '

http_separator:
    db      13, 10, 0

http_response:
    db      'bye lol', 10, 0

example_filename:
    db      'hello_world.txt', 0

filename:
    resb    256

http_request:
    resb    512

request_method:
    resb    8

method_post:
    db      'POST', 0

method_get:
    db      'GET', 0

method_head:
    db      'HEAD', 0

sigact:
    dq 1
    dq 0x04000000
    dq _start
    dq 0

bind_addr:
    dw 0x0002
    dw 0x5522
    dw 0
    dd 0

user_addr:
    dw 0
    dw 0
    dw 0
    dd 0

user_addr_len:
    dw 0

file_stat:
    resb 144

file_size:
    dq 0

file_size_string:
    resb 64

client_fd:
    dq 0

dynamic_file:
    dq 0

section .text

set_signal_handler:
    mov     rax, 13
    mov     rdi, 17  ; SIGCHLD
    mov     rsi, sigact   ; SIG_IGN
    mov     rdx, 0   ; oldact
    mov     r10, 8
    syscall          ; rt_sigaction(SIGCHLD, SIG_IGN, NULL);
    ret

fork:
    mov     rax, 57
    syscall
    ret

socket:
    mov     rax, 41
    mov     rdi, 2  ; AF_INET
    mov     rsi, 1  ; SOCK_STREAM
    mov     rdx, 0  ; protocol
    syscall         ; socket(AF_INET, SOCK_STREAM, proto)
    ret

bind:
    mov     rax, 0x31 ; bind
    mov     rdx, 0x10 ; addrlen
    mov     rsi, bind_addr  ; addr
    mov     rdi, rbx  ; sockfd
    syscall           ; bind(sockfd, addr, addrlen)
    ret

listen:
    mov     rax, 0x32 ; listen
    mov     rsi, 0x2  ; backlog
    mov     rdi, rbx  ; sockfd
    syscall           ; listen(sockfd, backlog)
    ret

write_bytes:
    mov     rax, 1
    syscall
    ret

write_string:
    push    rdx
    push    rdi
    mov     rdi, rsi
    mov     rcx, 0xffffffffffffffff
    mov     al, 0
    repne   scasb
    not     rcx
    dec     rcx

    mov     rdx, rcx    ; len
    pop     rdi         ; fd
    mov     rax, 1
    syscall             ; write(rdi, rsi, rdx)
    pop     rdx
    ret

write_file_to_fd:
    push    rdi

    mov     rax, 2
    mov     rdi, filename
    mov     rsi, 0
    syscall             ; open(example_filename, O_RDONLY)

    cmp     rax, 0
    jl      handle_404

    push rax

    mov     rax, 9
    mov     rdi, 0          ; addr
    mov     rsi, file_size    ; size
    mov     rsi, [rsi]
    mov     rdx, 0x1        ; PROT_READ
    mov     rcx, 0x2
    mov     r10, 0x2
    pop     r8              ; fd
    mov     r9, 0          ; offset
    syscall

    mov     rdx, file_size
    mov     rdx, [rdx]
    mov     rsi, rax
    pop     rdi
    call    write_bytes
    ret

read_into_buffer:
    mov     rax, 0
    syscall ; read(rdi, rsi, rdx)
    ret

global _start
_start:
    call set_signal_handler

    call    socket
    mov     rbx, rax ; holds our fd

    call    bind
    call    listen

accept_loop:
    mov     rax, 0x2b ; accept
    mov     rdi, rbx  ; sockfd

    mov     rsi, bind_addr  ; addr
    mov     rdx, user_addr_len ; addrlen
    syscall           ; accept(sockfd, addr, addrlen)
    mov     rdx, client_fd
    mov     [rdx], rax

    call    fork
    cmp     rax, 0
    jnz     close_sock_go_accept

process_request:
    mov     rdx, client_fd
    mov     rdx, [rdx]
    mov     rdi, rdx
    mov     rsi, http_request
    mov     rdx, 512
    call    read_into_buffer
    call    extract_info_from_request
    mov     rdi, dynamic_file
    mov     rdi, qword [rdi]
    cmp     rdi, 1
    jz      process_request_dynamic
process_request_static:
    call    handle_static_request
    jmp     process_request_cleanup
process_request_dynamic:
    call    handle_dynamic_request
    jmp     process_request_cleanup
process_request_cleanup:
    mov     rdx, client_fd
    mov     rdx, [rdx]
    mov     rax, 3
    mov     rdi, rdx
    syscall		; close(accept_fd)

jmp exithandler

close_sock_go_accept:
    mov     rdx, client_fd
    mov     rdx, [rdx]
    mov     rax, 3
    mov     rdi, rdx
    syscall		; close(accept_fd)

    jmp accept_loop

get_filename_from_request:
    mov     rdi, http_request
    call    strlen
    mov     rcx, rax
    mov     al, 0x2f
    repne   scasb
    cmp     rcx, 0
    jz      get_filename_fail
    dec     rdi
    add     rdi, 1
    mov     rcx, 0
get_filename_copy:
    cmp     rcx, 256
    jge     get_filename_fail
    mov     al, byte [rdi + rcx*1]
    cmp     al, 0
    jz      get_filename_terminate_string
    cmp     al, 0x3f
    jz      get_filename_terminate_string
    cmp     al, 0x20
    jz      get_filename_terminate_string
    mov     rsi, filename
    mov     byte [rsi + rcx*1], al
    inc     rcx
    jmp     get_filename_copy
get_filename_terminate_string:
    mov     byte [rsi + rcx*1], 0
    jmp     get_filename_ret
get_filename_fail:
    mov     rax, 0
get_filename_ret:
    ret

get_request_method:
    mov     rsi, http_request
    mov     rdi, request_method
    mov     rcx, 0
get_request_method_copy:
    cmp     rcx, 8
    jge     get_request_method_term
    mov     al, byte [rsi + rcx*1]
    cmp     al, 0x20
    jz      get_request_method_term
    mov     byte [rdi + rcx*1], al
    inc     rcx
    jmp     get_request_method_copy
get_request_method_term
    mov     byte [rdi + rcx*1], 0
    ret

get_file_info:
    mov     rax, 4
    mov     rdi, filename
    mov     rsi, file_stat
    syscall
    cmp     rax, 0
    jl      get_file_info_fail
    mov     rdi, file_size
    mov     rsi, file_stat
    mov     rcx, qword [rsi+48]
    mov     [rdi], rcx
    mov     rax, 1
    jmp     get_file_info_ret
get_file_info_fail:
    mov     rax, 0
get_file_info_ret:
    ret

itoa:
    push    rdi
    mov     rax, rsi
    mov     rbx, [rax]
    mov     rsi, 0
itoa_divide:
    mov     rax, rbx
    mov     rdx, 0
    mov     rcx, 10
    div     rcx
    add     rdx, 0x30
    mov     qword [rdi + rsi], rdx
    inc     rsi
    mov     rbx, rax
    cmp     rbx, 0
    jz      itoa_exit
    jmp     itoa_divide
itoa_exit:
    pop     rdi
    mov     rcx, rsi
    dec     rcx
    mov     rdx, 0
itoa_swap:
    mov     al, byte [rdi + rdx]
    mov     bl, byte [rdi + rcx]
    mov     byte [rdi + rcx], al
    mov     byte [rdi + rdx], bl
    inc     rdx
    dec     rcx
    cmp     rdx, rcx
    jl      itoa_swap
itoa_ret:
    ret

extract_info_from_request:
    call    get_request_method
    call    get_filename_from_request
    cmp     rax, 0
    jz      handle_404
    call    get_file_info
    cmp     rax, 0
    jz      handle_404
    mov     rdi, file_size_string
    mov     rsi, file_size
    call    itoa
    call    check_dynamic_request
    mov     rdi, dynamic_file
    mov     qword [rdi], rax
    ret

handle_static_request:
    mov     rdi, request_method
    mov     rsi, method_get
    call    strcmp
    cmp     rax, 1
    jz      handle_404

    mov     rdx, client_fd
    mov     rdx, [rdx]
    mov     rdi, rdx

    mov     rsi, http_response_200
    call    write_string
    mov     rdx, 16
    mov     rsi, http_header_content_length_dynamic
    call    write_bytes
    mov     rsi, file_size_string
    call    write_string
    mov     rsi, http_separator
    call    write_string

    mov     rsi, http_separator
    call    write_string

    call    write_file_to_fd
    ret

handle_dynamic_request:
    mov     rax, 33
    mov     rdi, client_fd
    mov     rdi, [rdi]
    mov     rsi, 0
    syscall

    mov     rax, 33
    mov     rdi, client_fd
    mov     rdi, [rdi]
    mov     rsi, 1
    syscall

    mov     rax, 33
    mov     rdi, client_fd
    mov     rdi, [rdi]
    mov     rsi, 2
    syscall

    mov     rax, 59
    mov     rdi, filename
    push    0
    push    http_request
    push    request_method
    push    filename
    mov     rsi, rsp
    mov     rdx, 0
    syscall
    call    failed_exec
    ret

failed_exec:
    mov     rdi, client_fd
    mov     rdi, [rdi]
    mov     rsi, message
    call    write_string
    call    exithandler
    ret

check_dynamic_request:
    mov     rdi, filename
    mov     si, word [rdi]
    mov     rax, 0
    cmp     si, 0x2f7a
    jnz     check_dynamic_request_ret
    mov     rax, 1
check_dynamic_request_ret:
    ret

handle_404:
    mov     rdi, client_fd
    mov     rdi, [rdi]
    mov     rsi, http_response_404
    call    write_string
    call    exithandler
    ret

strlen:
    push    rdi
    push    rcx
    mov     al, 0
    mov     rcx, 0xffffffffffffffff
    repne   scasb
    not     rcx
    dec     rcx
    mov     rax, rcx
    pop     rcx
    pop     rdi
    ret

strcmp:
    push    rdi
    push    rsi
    push    rcx
    call    strlen
    mov     rcx, rax
    xchg    rdi, rsi
    call    strlen
    xchg    rdi, rsi
    cmp     rcx, rax
    jnz     strcmp_notequal
    repe    cmpsb
    mov     rax, rcx
    cmp     rax, 0
    jz      strcmp_equal
strcmp_notequal:
    mov     rax, 1
strcmp_equal:
    pop     rcx
    pop     rsi
    pop     rdi
    ret

exithandler:
    mov    rax, 60
    mov    rdi, 2
    syscall


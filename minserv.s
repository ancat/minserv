section .data

message:
    db      'HTTP/1.1 200 OK', 13, 10, 'Content-Length: 8', 13, 10, 13, 10, 'bye lol', 10, 0

http_response_404:
    db      'HTTP/1.1 404 File Not Found', 13, 10, 'Content-Length: 4', 13, 10, 13, 10, '404', 10, 0

http_response_200:
    db      'HTTP/1.1 200 OK', 13, 10, 0

http_header_content_length:
    db      'Content-Length: 1024', 13, 10, 0

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

global client_fd
client_fd:
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
    mov     rsi, 0x40000    ; size
    mov     rdx, 0x1        ; PROT_READ
    mov     rcx, 0x2
    mov     r10, 0x2
    pop     r8              ; fd
    mov     r9, 0          ; offset
    syscall

    mov     rsi, rax
    pop     rdi
    call    write_string
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

handle_socket:
    mov     rdx, client_fd
    mov     rdx, [rdx]
    mov     rdi, rdx

    mov     rsi, http_request
    mov     rdx, 512
    call    read_into_buffer

    call    get_filename_from_request
    cmp     rax, 0
    jz      handle_404

    mov     rdx, client_fd
    mov     rdx, [rdx]
    mov     rdi, rdx

    mov     rsi, http_response_200
    call    write_string
    mov     rsi, http_header_content_length
    call    write_string
    mov     rsi, http_separator
    call    write_string

    call    write_file_to_fd

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
    mov     rsi, http_request
    cmp     dword [rsi], 0x20544547
    jnz     get_filename_fail
    add     rsi, 4
    cmp     byte [rsi], 0x2f
    jnz     get_filename_fail
    cmp     word [rsi], 0x2f2f
    jz     get_filename_fail
    add     rsi, 1
    mov     rcx, 0
get_filename_copy:
    cmp     rcx, 256
    jge     get_filename_fail
    mov     al, byte [rsi + rcx*1]
    cmp     al, 0
    jz      get_filename_terminate_string
    cmp     al, 0x20
    jz      get_filename_terminate_string
    cmp     al, 0x2e
    jz      get_filename_smell_check
get_filename_writeback:
    mov     rdi, filename
    mov     byte [rdi + rcx*1], al
    inc     rcx
    jmp     get_filename_copy
get_filename_smell_check:
    inc     rcx
    cmp     byte [rsi + rcx*1], 0x2e
    jz      get_filename_fail
    dec     rcx
    jmp     get_filename_writeback
get_filename_terminate_string:
    mov     byte [rdi + rcx*1], 0
    jmp     get_filename_ret
get_filename_fail:
    mov     rax, 0
get_filename_ret:
    ret

handle_404:
    mov     rdi, client_fd
    mov     rdi, [rdi]
    mov     rsi, http_response_404
    call    write_string
    call    exithandler
    ret

exithandler:
    mov    rax, 60
    mov    rdi, 2
    syscall


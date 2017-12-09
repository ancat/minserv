# Web Development With Assembly

![OwO What's this?](https://i.imgur.com/aZXSGwgl.png)

## Building and Running

Only dependencies are x86-64 linux kernel, nasm, and gcc.

To build the server: `make server`

To run: `strace -f ./minserv` (I wouldn't run it without `strace` tbh)

Cleanup (remove intermediary files, tests binary, etc): `make clean`

## Testing

Automated tests can be run using `make tests`. This will build a separate `tests` binary that tests the server code. Here's some sample output:
```
$ make tests
nasm -felf64 tests.s -o tests.o
gcc tests.o -nostartfiles -static -o tests
./tests
strlen_poop     test failed
strlen_empty    test passed
strcmp_equal    test passed
some tests failed! :(
make: *** [tests] Error 1
```
The exit code for all tests passing will be zero. Tests are located in `tests.s`.

Manual testing can be done using `curl`, for exampe:
- `curl -v localhost:8789/hello_world.txt`
- `curl -v localhost:8789/z/hello_world`

## Serving Content

Serving static content is as simple as dropping a file or directory in the same directory as the compiled binary. Dynamic content needs to be in the `z/` subdirectory and should have the `+x` bit set. Any executable or script with the proper shebang line will work fine. Dynamic scripts are responsible for setting their own headers.

## Warnings

1. It's bad code. This code is like it was written by a babby who only just learned about global variables and doesn't know how to comment code, mixed in with shellcode.
2. Bugs. Some of which might kill you. There's very little error checking right now.

## To Do

1. Tests
2. Handle syscall error cases
3. Support for apps written in assembly (loading it instead of just execve'ing everything)

## Why did you do this?

Questions like that don't help anyone.

.PHONY: tests server

server:
	nasm -felf64 main.s -o main.o
	gcc main.o -nostartfiles -static -o minserv

tests:
	nasm -felf64 tests.s -o tests.o
	gcc tests.o -nostartfiles -static -o tests
	./tests

clean:
	rm -f tests.o minserv.o main.o tests


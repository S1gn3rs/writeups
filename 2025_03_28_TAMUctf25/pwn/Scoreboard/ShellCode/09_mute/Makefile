# Get: libseccomp-dev:i386 seccomp:i386 libc6-dev-i386
# http://syscalls.kernelgrok.com/

CC=gcc
FLAGS=-m32 -Wall -Wextra -ggdb -no-pie -lseccomp
EXTRA_FLAGS=-z execstack

all:
	$(CC) $(FLAGS) *.c -o bin

clean:
	rm bin

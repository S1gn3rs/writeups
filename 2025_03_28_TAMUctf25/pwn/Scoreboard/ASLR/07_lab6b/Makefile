CC=gcc
FLAGS=-m32 -Wall -Wextra -ggdb

all:
	$(CC) $(FLAGS) -pie -fpie -fno-stack-protector -z relro -z now *.c -o bin

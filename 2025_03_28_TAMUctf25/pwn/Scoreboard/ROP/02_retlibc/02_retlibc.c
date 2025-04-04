#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../general.h"

char storage[256] = {0};

void store_data(char *buf) {
    char local_buffer[64] = {0};

    strcpy(local_buffer, buf);
    memcpy(storage, local_buffer, 64);
    printf("Securely stored!\n");
}

int main() {
    system("echo -n \"Hey man!\"");
    init();

    printf("Welcome to STT's storage system!\n");
    printf("Input what you want to store in our secure system!\n");

    char to_store[128] = {0};
    read(STDIN_FILENO, to_store, 127);

    store_data(to_store);
}
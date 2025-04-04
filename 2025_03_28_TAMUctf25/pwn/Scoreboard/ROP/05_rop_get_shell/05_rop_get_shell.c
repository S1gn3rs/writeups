#include <stdlib.h>
#include <stdio.h>
#include "../general.h"

char storage[256] = {0};

void welcome_user() {
    char buffer[128] = {0};

    printf("Please give me your username.\n");
    printf("Input:\n");
    fgets(buffer, 256, stdin);
    printf("Welcome %s!", buffer);
}

int main() {
    init();

    welcome_user();

    return 0;
}
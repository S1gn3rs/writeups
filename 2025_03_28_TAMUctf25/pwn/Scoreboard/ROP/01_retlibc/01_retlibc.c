#include <stdlib.h>
#include <stdio.h>
#include "../general.h"

void welcome_user() {
    char buffer[128] = {0};

    system("echo \"Can you ret2system()?\"");
    printf("Input:\n");

    gets(buffer);

    printf("Welcome to your first ret2libc %s!", buffer);
}

int main() {
    init();

    welcome_user();

    return 0;
}
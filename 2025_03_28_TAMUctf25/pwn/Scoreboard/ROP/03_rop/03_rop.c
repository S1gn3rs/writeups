#include <stdlib.h>
#include <stdio.h>
#include "../general.h"

void welcome_user() {
    char buffer[128] = {0};

    printf("Insert ROP chain here:\n");
    gets(buffer);
    printf("Welcome to your first ROP %s!", buffer);
}

int main() {
    init();

    welcome_user();

    return 0;
}
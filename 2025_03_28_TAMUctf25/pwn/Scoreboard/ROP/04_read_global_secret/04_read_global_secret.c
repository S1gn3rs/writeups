#include <stdlib.h>
#include <stdio.h>
#include "../general.h"
#include "../get_flag.h"

char *target;
void welcome_user() {
    char buffer[128] = {0};

    printf("Bet you can't read my sercrets!\n");
    printf("Input:\n");
    fgets(buffer, 256, stdin);
    printf("Welcome %s!", buffer);
}

int main() {
    init();

    target = get_flag();

    welcome_user();

    return 0;
}
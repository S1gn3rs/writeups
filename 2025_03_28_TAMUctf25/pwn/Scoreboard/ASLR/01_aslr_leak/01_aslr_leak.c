#include <stdio.h>
#include <stdlib.h>
#include "../general.h"
#include "../get_flag.h"

void i_am_rly_leet() {
    printf("You found me!\nGood job!\n");
    printf("Here is your flag: %s!\n", get_flag());
    return;
}

void challenge() {
    char my_string[16];
    printf("Win Func @ %p\n", i_am_rly_leet);
    fgets(my_string,40,stdin);
}

int main() {
    init();

    challenge();

    return 0;
}
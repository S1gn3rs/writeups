#include <stdio.h>
#include <unistd.h>
#include "../get_flag.h"

#define BUFFER_LEN 128

unsigned int target = 0;

void vuln() {
    char buffer[BUFFER_LEN] = {0};
    read(0, buffer, BUFFER_LEN-1);

    printf(buffer);

    if (target != 0) {
        printf("Success! You hit the target!\n");
        printf("Here is your flag: %s\n", get_flag());
    } else {
        printf("Oops, not quite!\n");
    }
}

int main() {
    vuln();
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "../general.h"

#define BUFFER_LEN 128

void parse_loop() {
    char buf[1024];

    printf("Welcome to my parser!\n");
    while (1) {
        printf("Input: ");
        char *result = fgets(buf, 1024, stdin);
        if (!result)
            return;

        char *val = strtok(result, " ");
        if (val == NULL) {
            continue;
        }

        printf(val);
    }
}

int main() {
    init();
    parse_loop();
}

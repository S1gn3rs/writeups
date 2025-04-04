#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../general.h"

#define BUFFER_LEN 256
char buffer[BUFFER_LEN] = {0};

void do_print() {
    printf("Here is your buffer: ");
    printf(buffer);
    printf("\n");
}

void do_write() {
    char local_buffer[BUFFER_LEN/2] = {0};

    printf("What to you want to write: ");

    int i = 0;
    int res;
    res = read(STDIN_FILENO, local_buffer, 1);
    while (res == 1 && local_buffer[i] != '\n') {
        i++;
        res = read(STDIN_FILENO, local_buffer+i, 1);
    }
    local_buffer[i] = '\0';

    memcpy(buffer, local_buffer, strlen(local_buffer));
}

void main_loop(char *username) {
    char c[64];

    strcpy(c, username);
    printf("HEY %s!\n", c);
    memset(c, 0, 64);

    while (1) {
        printf("\nInput: ");

        do {
            c[0] = getchar();
        } while(c[0] == '\n');


        // Eat until a '\n'.
        while(getchar() != '\n') {}

        switch (c[0]) {
            case 'p': case 'P':
                do_print();
                break;
            case 'w': case 'W':
                do_write();
                break;
            case 'e': case 'E':
                return;
            default:
                printf("Unknown command '%c'.\n", c[0]);
                printf("Usage: 'w' for writting, 'p' for reading, 'e' for exiting.\n");
        }
    }
}

int main() {
    init();

    char username[64] = {0};
    printf("What is your name sir: ");
    scanf("%60s", username);

    main_loop(username);
    printf("Thanks for using this amazing service\n");

    return 0;
}
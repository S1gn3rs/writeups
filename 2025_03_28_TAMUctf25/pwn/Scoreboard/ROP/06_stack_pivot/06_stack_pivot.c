#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../general.h"

char storage[256] = {0};

int authenticate_user(char *username) {
    char pass[128] = {0};
    fgets(pass, 148, stdin);

    return (strcmp(username, "STT") == 0  && strcmp(pass, "ASDGRCVWA") == 0);
}

int main() {
    init();

    printf("Hello, please give me you username: ");

    char username[512] = {0};
    fgets(username, 511, stdin);

    if (authenticate_user(username)) {
        printf("Welcome %s.", username);
    } else {
        printf("Get out hacker!");
    }

    return 0;
}
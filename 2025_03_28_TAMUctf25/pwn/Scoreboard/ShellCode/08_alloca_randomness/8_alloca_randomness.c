#include <time.h>
#include <stdlib.h>

#include "../shellcode_base.c"

void welcome_user() {
    char username[256] = {0};

    // Insert random padding so if we have any vulnerabilities
    // them hackers will have a hard time attacking it.
    int random_size = rand() % 50 + 50;
    char padding[random_size];

    printf("What is your username: ");
    scanf("%s", username);
    printf("Welcome %s. Hope the %d bytes of padding didn't make it harder.\n", username, random_size);
}

int main() {
    init();

    srand(time(NULL));

    welcome_user();
}
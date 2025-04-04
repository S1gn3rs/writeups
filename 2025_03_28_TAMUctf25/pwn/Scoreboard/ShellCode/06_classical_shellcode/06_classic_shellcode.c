#include "../shellcode_base.c"

void welcome_user() {
    char username[256] = {0};
    printf("What is your username: ");
    gets(username);
    printf("Welcome %s...\n", username);
}

int main() {
    init();

    welcome_user();
}
#include "../shellcode_base.c"

void welcome_user() {
    char username[10] = {0};
    printf("What is your username: ");
    scanf("%s", username);
    printf("Welcome %s...\n", username);
}

int main() {
    init();

    welcome_user();
}
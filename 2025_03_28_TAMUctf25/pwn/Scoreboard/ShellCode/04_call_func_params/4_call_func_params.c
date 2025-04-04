#include "../shellcode_base.c"
#include <time.h>
#include <stdlib.h>


char *secret;
unsigned int r;

void win(unsigned int a, unsigned int b) {
    if (a != 0xdeadbeef) {
        printf("Variable a must be equal to 0xdeadbeef. It was equal to: 0x%x", a);
        exit(-1);
    }

    if (b != r) {
        printf("Variable b must be equal to 0x%x. It was equal to: 0x%x", r, b);
        exit(-2);
    }

    printf("Secret: %s\n", secret);
}

int main() {
    init();
    printf("Can you redirect code execution and call win with the right parameters?\n");

    // Load the secret
    secret = get_secret();

    // Get rand value
    srand(time(NULL));
    r = rand();
    printf("The random value is %x\n", r);

    // read to executable memory
    void *shellcode = read_bytes_to_mmap_memory(BUF_LEN);

    // Limit the possible syscalls the user can call
    turn_on_basic_sandbox();

    // execute user payload
    ((void (*)(void))shellcode)();
}
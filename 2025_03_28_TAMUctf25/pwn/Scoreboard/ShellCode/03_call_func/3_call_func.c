#include "../shellcode_base.c"

char *secret;

void win() {
    printf("Secret: %s\n", secret);
}

int main() {
    init();
    printf("Can you redirect code execution and call win?\n");

    // Load the secret
    secret = get_secret();

    // read to executable memory
    void *shellcode = read_bytes_to_mmap_memory(BUF_LEN);

    // Limit the possible syscalls the user can call
    turn_on_basic_sandbox();

    // execute user payload
    ((void (*)(void))shellcode)();
}
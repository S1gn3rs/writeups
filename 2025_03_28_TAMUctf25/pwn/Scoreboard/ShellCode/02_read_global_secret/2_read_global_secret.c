#include "../shellcode_base.c"

char secret[50];
int main() {
    init();
    printf("Bet you can't read this global variable!\n");

    // Load the secret
    char *_secret = get_secret();
    memcpy(secret, _secret, strlen(_secret));

    // read to executable memory
    void *shellcode = read_bytes_to_mmap_memory(BUF_LEN);

    // Limit the possible syscalls the user can call
    turn_on_basic_sandbox();

    // execute user payload
    ((void (*)(void))shellcode)();
}
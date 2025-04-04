#include "../shellcode_base.c"

int main() {
    init();
    printf("Bet you can't read this local variable!\n");

    // Load the secret
    char secret[50];
    char *_secret = get_secret();
    memcpy(secret, _secret, strlen(_secret));

    // read to executable memory
    void *shellcode = read_bytes_to_mmap_memory(BUF_LEN);

    // Limit the possible syscalls the user can call
    turn_on_basic_sandbox();

    // execute user payload
    ((void (*)(void))shellcode)();
}
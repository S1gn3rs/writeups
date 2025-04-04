#include "../shellcode_base.c"

int main() {
    init();
    printf("Can you open the file '/home/ctf/flag', read it, and then write it on the screen?\n");

    // read to executable memory
    void *shellcode = read_bytes_to_mmap_memory(BUF_LEN);

    // Limit the possible syscalls the user can call
    turn_on_basic_sandbox();

    // execute user payload
    ((void (*)(void))shellcode)();
}
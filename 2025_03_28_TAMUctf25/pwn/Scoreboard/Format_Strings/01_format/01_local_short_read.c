#include <stdio.h>
#include <unistd.h>
#include "../get_flag.h"

#define BUFFER_LEN 5

char buffer[BUFFER_LEN] = {0};

void vuln() {
    char *secret_value = get_flag();
    printf(buffer);
}

int main() {
    read(0, buffer, BUFFER_LEN-1);
    vuln();
}

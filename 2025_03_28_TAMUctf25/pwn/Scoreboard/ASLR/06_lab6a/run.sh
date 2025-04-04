#!/bin/sh
exec /usr/bin/env LD_PRELOAD=/home/ctf/libc-2.23.so /home/ctf/bin "$@"

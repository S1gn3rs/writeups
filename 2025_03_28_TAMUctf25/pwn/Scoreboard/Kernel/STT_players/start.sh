#!/bin/bash

# compile the exploit with static since there is no libc.so.6 available
gcc -static exploit.c -o exploit || exit

rm -rf fs
mkdir fs

pushd ./fs
# unpack the filesystem
cpio -idv < ../rootfs.cpio
# copy the exploit into the filesystem
cp ../exploit .
rm ../exploit
# pack the filesytem with the new exploit
find . -print0 | cpio --null -ov --format=newc > ../rootfs.cpio
popd

rm -rf fs

qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr pti=off quiet" \
    -monitor /dev/null \
    -nographic
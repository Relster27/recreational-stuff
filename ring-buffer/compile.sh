#!/bin/bash

# Usage: ./compile.sh <ARG>

if [[ "$1" == "DEBUG" ]]; then
        gcc ringbuf.c -o ringbuf -fno-stack-protector -g -DDEBUG_MODE
        chmod +x ringbuf
        gdb -q ./ringbuf
        # ./ringbuf
else
        # gcc ringbuf.c -o ringbuf -fstack-protector -Wl,-z,relro,-z,now -Wall -s
        gcc ringbuf.c -o ringbuf -fno-stack-protector -g
        chmod +x ringbuf
        ./ringbuf
fi

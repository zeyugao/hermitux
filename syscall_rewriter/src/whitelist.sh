#!/bin/bash

./rewrite_syscalls test --prev \
                        0x471779 0x4023cd 0x402cc5 \
                        0x471529 0x47be61 \
                        0x449ff9 0x4490d9 \
                        --all \
                         | grep will
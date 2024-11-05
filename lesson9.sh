#!/bin/bash
cd
./ecc Ebpf/Ebpf/lesson9/runqlat.bpf.c Ebpf/Ebpf/lesson9/runqlat.h
sudo ./ecli run Ebpf/Ebpf/lesson9/package.json
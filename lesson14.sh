#!/bin/bash

cd
./ecc Ebpf/Ebpf/lesson14-TCP-RTT/tcprtt.bpf.c Ebpf/Ebpf/lesson14-TCP-RTT/tcprtt.h
sudo ./ecli Ebpf/Ebpf/lesson14-TCP-RTT/package.json

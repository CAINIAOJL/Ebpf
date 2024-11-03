#!/bin/bash
cd
./ecc Ebpf/Ebpf/lesson7/execsnoops.bpf.c Ebpf/Ebpf/lesson7/execsnoop.h
sudo ./ecli Ebpf/Ebpf/lesson7/package.json
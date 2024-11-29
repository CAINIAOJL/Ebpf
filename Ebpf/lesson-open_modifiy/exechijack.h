// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#define FILENAME_LEN_MAX 50
#define TEXT_LEN_MAX 20

#define TASK_COMM_LEN 16
struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};
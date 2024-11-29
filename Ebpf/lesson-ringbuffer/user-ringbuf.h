#pragma once

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	char comm[TASK_COMM_LEN];
};

struct user_sample {
	int i;
	char comm[TASK_COMM_LEN];
};
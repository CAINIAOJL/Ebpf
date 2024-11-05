#ifndef __HARDIRQS_H
#define __HARDIRQS_H

#define MAX_SLOTS 20

struct info {
	__u64 count;
	__u32 slots[MAX_SLOTS];
};

#endif /* HARDIRQS_H */
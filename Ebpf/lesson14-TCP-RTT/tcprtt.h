#ifndef TCPRTT_H
#define TCPRTT_H

#define MAX_SLOTS 27

struct hist {
    unsigned long long latency;
    unsigned long long cnt;
    unsigned long long slots[MAX_SLOTS];
};



#endif
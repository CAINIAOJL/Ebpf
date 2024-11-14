#ifndef GOROUTINE_H
#define GOROUTINE_H

enum goroutine_status {
    IDLE,
    RUNNABLE,
    RUNNING,
    SYSCALL,
    WAITING,
    MORIBUND_UNUSED,
    DEAD,
    ENQUEUE_UNUSED,
    COPYSTACK,
    PREEMPTED,
};

/*
    IDLE：空闲状态。表示 goroutine 当前没有执行任何任务，处于空闲等待状态。
RUNNABLE：可运行状态。表示 goroutine 已经准备好运行，但还没有被调度器选中执行。它可能正在等待调度器的调度。
RUNNING：运行状态。表示 goroutine 当前正在 CPU 上执行。
SYSCALL：系统调用状态。表示 goroutine 正在执行系统调用（如 I/O 操作），此时它可能会阻塞等待系统调用的完成。
WAITING：等待状态。表示 goroutine 正在等待某个条件（如通道操作、锁、计时器等）的满足。
MORIBUND_UNUSED：垂死未使用状态。这个状态在当前的 Go 实现中可能不再使用，或者用于表示 goroutine 正在被清理但尚未完成的状态。名称中的 "UNUSED" 表明这个状态在当前版本中可能不再被使用。
DEAD：死亡状态。表示 goroutine 已经执行完毕，不再有任何活动。
ENQUEUE_UNUSED：入队未使用状态。这个状态同样表明它可能不再被使用，或者用于内部处理 goroutine 队列时的某种特殊状态。
COPYSTACK：复制栈状态。在 Go 的并发模型中，当 goroutine 的栈需要增长时，可能会触发栈的复制操作。这个状态表示 goroutine 正在执行栈的复制过程。
PREEMPTED：抢占状态。表示 goroutine 被调度器抢占，以便让其他 goroutine 运行。这是 Go 运行时实现公平调度的一种方式。
*/

struct goroutine_execute_data {
    enum goroutine_status status;
    unsigned long goid;
    int pid;
    int tgid;
};

#endif

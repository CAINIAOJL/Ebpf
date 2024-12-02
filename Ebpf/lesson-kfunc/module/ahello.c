#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>


static int hello_init(void) {
    printk(KERN_INFO "I bear a charmed life.\n");
    return 0;
}

static void hello_exit(void) {
    printk(KERN_INFO "Out, Out, brief candle!\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianglei");
MODULE_DESCRIPTION("A simple hello world module");
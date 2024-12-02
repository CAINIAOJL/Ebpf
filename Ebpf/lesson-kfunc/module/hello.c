//编写内核模块
#include <linux/module.h>
//在Ubuntu下，在wsl下不完整
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

//声明kfunc原型
__bpf_kfunc int bpf_strstr(const char* str, u32 str__sz, const char *substr, u32 substr__sz);
//开始kfunc定义
__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_strstr(const char* str, u32 str__sz, const char *substr, u32 substr__sz) {
    if (substr__sz == 0) {
        return 0;
    }

    if(substr__sz > str__sz) {
        return -1;
    }

    for (size_t i = 0; i <= str__sz - substr__sz; i++) {
        size_t j = 0;
        while(j < substr__sz && str[i + j] == substr[j]) {
            j++;
        }

        if (j == substr__sz) {
            return i;
        }
    }

    return -1;
}
//结束定义
__bpf_kfunc_end_defs();

//定义BTF kfunc ID集
BTF_KFUNCS_START(bpf_kfunc_example_ids_set);
BTF_ID_FLAGS(func, bpf_strstr);
BTF_KFUNCS_END(bpf_kfunc_example_ids_set);

//注册kfunc ID集
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

//模块加载时执行的函数
static int __init hello_init(void) {
    int ret;

    printk(KERN_INFO "Hello world!\n");

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);

    if (ret) {
        pr_err("bpf_kfunc_example: 注册BTF kfunc ID集失败\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: 模块加载成功\n");
    return 0;
}

static void __exit hello_exit(void) {
    unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    printk(KERN_INFO "再见，世界！\n");
}
//定义模块的初始化和退出点的宏
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cainiao");
MODULE_DESCRIPTION("一个简单的模块！");
MODULE_VERSION("1.0");

/*
#include <linux/init.h>       // 模块初始化宏
#include <linux/module.h>     // 加载模块的核心头文件
#include <linux/kernel.h>     // 内核日志宏
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

/* 声明 kfunc 原型 */
//__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz);

/* 开始 kfunc 定义 */
//__bpf_kfunc_start_defs();

/* 定义 bpf_strstr kfunc */
/*__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz)
{
    // 边界情况：如果 substr 为空，返回 0（假设空字符串在开始处找到）
    if (substr__sz == 0)
    {
        return 0;
    }
    // 边界情况：如果子字符串比主字符串长，则无法找到
    if (substr__sz > str__sz)
    {
        return -1; // 返回 -1 表示未找到
    }
    // 遍历主字符串，考虑大小限制
    for (size_t i = 0; i <= str__sz - substr__sz; i++)
    {
        size_t j = 0;
        // 将子字符串与当前主字符串位置进行比较
        while (j < substr__sz && str[i + j] == substr[j])
        {
            j++;
        }
        // 如果整个子字符串都匹配
        if (j == substr__sz)
        {
            return i; // 返回第一次匹配的索引
        }
    }
    // 如果未找到子字符串，返回 -1
    return -1;
}

/* 结束 kfunc 定义 */
//__bpf_kfunc_end_defs();

/* 定义 BTF kfuncs ID 集 */
/*BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

/* 注册 kfunc ID 集 */
/*static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/* 模块加载时执行的函数 */
/*static int __init hello_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, world!\n");
    /* 注册 BPF_PROG_TYPE_KPROBE 的 BTF kfunc ID 集 */
    /*ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("bpf_kfunc_example: 注册 BTF kfunc ID 集失败\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: 模块加载成功\n");
    return 0; // 成功返回 0
}

/* 模块卸载时执行的函数 */
/*static void __exit hello_exit(void)
{
    /* 取消注册 BTF kfunc ID 集 */
    /*unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    printk(KERN_INFO "再见，世界！\n");
}

/* 定义模块的初始化和退出点的宏 */
/*module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");                 // 许可证类型（GPL）
MODULE_AUTHOR("Your Name");            // 模块作者
MODULE_DESCRIPTION("一个简单的模块"); // 模块描述
MODULE_VERSION("1.0");                 // 模块版本
*/
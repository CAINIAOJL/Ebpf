#include <stdio.h>
#include <stdint.h>
#include <string.h>

// 函数声明
void buf_to_hex(const uint8_t *buf, size_t len, char *hex_str);

int main() {
    // 示例缓冲区
    uint8_t buffer[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    size_t buffer_len = sizeof(buffer) / sizeof(buffer[0]);

    // 分配足够的空间来存储十六进制字符串
    // 每个字节需要2个字符来表示（例如0x12需要"12"），再加上一个终止符'\0'
    char hex_str[buffer_len * 2 + 1];

    // 调用函数将缓冲区转换为十六进制字符串
    buf_to_hex(buffer, buffer_len, hex_str);

    // 打印结果
    printf("Hexadecimal representation: %s\n", hex_str);

    return 0;
}

// 函数定义
void buf_to_hex(const uint8_t *buf, size_t len, char *hex_str) {
    for(size_t i = 0; i < len; i++) {
        sprintf(hex_str + 2 * i, "%02x", buf[i]);
    }
}
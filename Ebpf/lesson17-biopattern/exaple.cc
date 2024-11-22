#include <iostream>
#include <chrono>
#include <cstdlib>

const size_t ROWS = 10000; // 行数
const size_t COLS = 10000; // 列数

int main() {
    // 记录程序开始时间
    auto start = std::chrono::high_resolution_clock::now();

    std::cout << "开始分配内存..." << std::endl;

    // 动态分配二维数组
    int** largeArray = new int*[ROWS];
    for (size_t i = 0; i < ROWS; ++i) {
        largeArray[i] = new int[COLS];
    }

    std::cout << "内存分配完成，开始操作数据..." << std::endl;

    // 对数组进行简单操作（填充数据）
    for (size_t i = 0; i < ROWS; ++i) {
        for (size_t j = 0; j < COLS; ++j) {
            largeArray[i][j] = (i + j) % 100; // 填充数据
        }
    }

    std::cout << "数据操作完成，开始释放内存..." << std::endl;

    // 释放内存
    for (size_t i = 0; i < ROWS; ++i) {
        delete[] largeArray[i];
    }
    delete[] largeArray;

    std::cout << "内存释放完成！" << std::endl;

    // 记录程序结束时间
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "程序执行耗时: " << elapsed.count() << " 秒" << std::endl;

    return 0;
}

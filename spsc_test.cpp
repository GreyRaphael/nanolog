#include "spsc.hpp"

#include <print>
#include <thread>

void test_heap() {
    // 1. 初始化一个 64KB 的队列
    SPSCVarQueueHeap queue(64 * 1024);
    // 测试发送 1e8 条消息
    auto test_count = 1e8;

    // 2. 启动消费者线程
    std::thread consumer([&] {
        int expected_val = 0;
        int received_count = 0;

        while (received_count < test_count) {
            bool success = queue.tryPop([&](SPSCVarQueueHeap::MsgHeader* h) {
                // 获取消息头之后的数据指针
                int* data_ptr = reinterpret_cast<int*>(h + 1);

                // 校验数据准确性
                if (*data_ptr != expected_val) {
                    std::println("error: expected={}, recv={}", expected_val, *data_ptr);
                }

                expected_val++;
                received_count++;
            });

            if (!success) {
                // 队列为空，忙等或短暂睡眠以降低 CPU 占用
                std::this_thread::yield();
            }
        }
        std::println("consumer{} recv {}", std::this_thread::get_id(), received_count);
    });

    // 3. 启动生产者线程
    std::thread producer([&] {
        for (int i = 0; i < test_count; ++i) {
            // 发送 int 类型数据，大小为 sizeof(int)
            while (!queue.tryPush(sizeof(int), [&](SPSCVarQueueHeap::MsgHeader* h) {
                h->msg_type = 1;  // 设置自定义消息类型
                int* data_ptr = reinterpret_cast<int*>(h + 1);
                *data_ptr = i;
            })) {
                // 队列满了，重试
                std::this_thread::yield();
            }
        }
        std::println("producer{} send {}", std::this_thread::get_id(), test_count);
    });

    // 4. 等待线程结束
    producer.join();
    consumer.join();

    std::println("pass!");
}

constexpr uint32_t QUEUE_SIZE = 64 * 1024;
using SPSCVarQueueOnStack = SPSCVarQueueStack<64 * 1024>;

void test_stack() {
    // 实例化一个 64KB 的队列 on stack
    SPSCVarQueueOnStack queue;
    auto test_count = 1e8;

    std::thread consumer([&] {
        int expected_val = 0;
        int received_count = 0;

        while (received_count < test_count) {
            bool success = queue.tryPop([&](SPSCVarQueueOnStack::MsgHeader* h) {
                // 获取消息头之后的数据指针
                int* data_ptr = reinterpret_cast<int*>(h + 1);

                // 校验数据准确性
                if (*data_ptr != expected_val) {
                    std::println("error: expected={}, recv={}", expected_val, *data_ptr);
                }

                expected_val++;
                received_count++;
            });

            if (!success) {
                // 队列为空，忙等或短暂睡眠以降低 CPU 占用
                std::this_thread::yield();
            }
        }
        std::println("consumer{} recv {}", std::this_thread::get_id(), received_count);
    });
    std::thread producer([&] {
        for (int i = 0; i < test_count; ++i) {
            // 发送 int 类型数据，大小为 sizeof(int)
            while (!queue.tryPush(sizeof(int), [&](SPSCVarQueueOnStack::MsgHeader* h) {
                h->msg_type = 1;  // 设置自定义消息类型
                int* data_ptr = reinterpret_cast<int*>(h + 1);
                *data_ptr = i;
            })) {
                // 队列满了，重试
                std::this_thread::yield();
            }
        }
        std::println("producer{} send {}", std::this_thread::get_id(), test_count);
    });

    producer.join();
    consumer.join();
    std::println("pass!");
}

int main() {
    // // SPSC Queue on Heap
    // test_heap();
    // SPSC Queue on Stack
    test_stack();
}
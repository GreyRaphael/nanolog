#pragma once
#include <atomic>
#include <cstdint>
#include <new>  // hardware_destructive_interference_size

// 使用 C++20 Concepts 约束回调函数
template <typename T, typename Header>
concept MsgWriter = requires(T t, Header* h) { t(h); };

template <typename T, typename Header>
concept MsgReader = requires(T t, Header* h) { t(h); };

template <uint32_t Bytes>
class SPSCVarQueueStack {
   public:
    struct MsgHeader {
        uint16_t size;  // 整个消息的大小（含 header）
        uint16_t msg_type;
        // uint32_t userdata;
    };

    static constexpr uint32_t BLK_SIZE = sizeof(MsgHeader);
    static constexpr uint32_t BLK_CNT = Bytes / BLK_SIZE;

    // 解决虚假共享的对齐长度
#ifdef __cpp_lib_hardware_interference_size
    static constexpr size_t CacheLine = std::hardware_destructive_interference_size;
#else
    static constexpr size_t CacheLine = 64;
#endif

    SPSCVarQueueStack() = default;

    // 禁止拷贝
    SPSCVarQueueStack(const SPSCVarQueueStack&) = delete;
    SPSCVarQueueStack& operator=(const SPSCVarQueueStack&) = delete;

    /**
     * @brief 生产者分配空间
     * @return 返回 Header 指针，若空间不足返回 nullptr
     */
    [[nodiscard]] MsgHeader* alloc(uint16_t data_size) {
        const uint32_t total_size = data_size + sizeof(MsgHeader);
        const uint32_t blk_needed = (total_size + BLK_SIZE - 1) / BLK_SIZE;

        // 空间检查：如果缓存的空闲块不足
        if (blk_needed >= p.free_write_cnt_cache) {
            uint32_t r_idx = c_shared.read_idx.load(std::memory_order_acquire);

            if (r_idx <= p.write_idx_cache) {
                p.free_write_cnt_cache = BLK_CNT - p.write_idx_cache;

                // 检查末尾空间是否足够。若不足，尝试回绕到头部
                if (blk_needed >= p.free_write_cnt_cache) {
                    // 只有当头部有足够空间且 r_idx != 0 时才回绕
                    if (r_idx > blk_needed) {
                        // 1. 先确保头部第一个块 size=0 (不可读)
                        std::atomic_ref<uint16_t>(blk[0].size).store(0, std::memory_order_relaxed);
                        // 2. 写入哨兵值 1，标记末尾跳过
                        std::atomic_ref<uint16_t>(blk[p.write_idx_cache].size).store(1, std::memory_order_release);

                        p.write_idx_cache = 0;
                        p.free_write_cnt_cache = r_idx;
                    } else {
                        return nullptr;  // 彻底没空间了
                    }
                }
            } else {
                p.free_write_cnt_cache = r_idx - p.write_idx_cache;
            }

            // 再次确认最终可用空间（预留一个块防止 write_idx == read_idx 导致歧义）
            if (p.free_write_cnt_cache <= blk_needed) return nullptr;
        }

        p.pending_size = total_size;
        p.pending_blk_sz = blk_needed;
        return &blk[p.write_idx_cache];
    }

    /**
     * @brief 生产者提交
     */
    void push() {
        MsgHeader& current_msg = blk[p.write_idx_cache];

        // 1. 预先清空下一个可能的起始块，防止消费者越界读到旧数据
        uint32_t next_idx = p.write_idx_cache + p.pending_blk_sz;
        if (next_idx < BLK_CNT) {
            std::atomic_ref<uint16_t>(blk[next_idx].size).store(0, std::memory_order_relaxed);
        }

        // 2. 写入当前消息大小 (Release 语义确保数据可见性)
        std::atomic_ref<uint16_t>(current_msg.size).store(p.pending_size, std::memory_order_release);

        // 3. 更新索引
        p.write_idx_cache = (next_idx == BLK_CNT) ? 0 : next_idx;
        p.free_write_cnt_cache -= p.pending_blk_sz;
        p_shared.write_idx.store(p.write_idx_cache, std::memory_order_release);
    }

    /**
     * @brief 消费者获取消息
     */
    [[nodiscard]] MsgHeader* front() {
        uint16_t s = std::atomic_ref<uint16_t>(blk[c.read_idx_cache].size).load(std::memory_order_acquire);

        // 处理哨兵：如果 size == 1，说明该跳到头部了
        if (s == 1) {
            c.read_idx_cache = 0;
            s = std::atomic_ref<uint16_t>(blk[0].size).load(std::memory_order_acquire);
        }

        if (s == 0) return nullptr;
        return &blk[c.read_idx_cache];
    }

    /**
     * @brief 消费者弹出
     */
    void pop() {
        // 注意：pop 必须基于 front 确定的位置
        uint16_t s = blk[c.read_idx_cache].size;
        uint32_t blk_sz = (s + BLK_SIZE - 1) / BLK_SIZE;

        c.read_idx_cache += blk_sz;
        if (c.read_idx_cache >= BLK_CNT) c.read_idx_cache = 0;

        c_shared.read_idx.store(c.read_idx_cache, std::memory_order_release);
    }

    // 辅助函数
    template <MsgWriter<MsgHeader> Writer>
    bool tryPush(uint16_t size, Writer writer) {
        MsgHeader* h = alloc(size);
        if (!h) return false;
        writer(h);
        push();
        return true;
    }

    template <MsgReader<MsgHeader> Reader>
    bool tryPop(Reader reader) {
        MsgHeader* h = front();
        if (!h) return false;
        reader(h);
        pop();
        return true;
    }

   private:
    // 1. 缓冲区
    alignas(CacheLine) MsgHeader blk[BLK_CNT];

    // 2. 生产者私有数据（独占 CacheLine）
    struct alignas(CacheLine) {
        std::atomic<uint32_t> write_idx{0};  // 虽然是原子的，但主要由生产者写
    } p_shared;

    struct {
        uint32_t write_idx_cache = 0;
        uint32_t free_write_cnt_cache = BLK_CNT;
        uint32_t pending_size = 0;
        uint32_t pending_blk_sz = 0;
    } p;

    // 3. 消费者私有数据（独占 CacheLine）
    struct alignas(CacheLine) {
        std::atomic<uint32_t> read_idx{0};
    } c_shared;

    struct {
        uint32_t read_idx_cache = 0;
    } c;
};
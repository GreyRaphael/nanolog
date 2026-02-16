#pragma once
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <type_traits>
#include <vector>

namespace nanolog {

enum class LogLevel : uint8_t { INFO,
                                WARN,
                                CRIT };

// 配置参数
// 1. 每个线程的 SPSC 队列大小 (8MB)，足够大以应对突发流量, 16MB MSVC无法运行
constexpr uint32_t THREAD_QUEUE_SIZE = 8 * 1024 * 1024;
// 2. 单条日志最大长度 (栈上缓存大小)
constexpr size_t MAX_LOG_LINE_SIZE = 512;

// 辅助函数：获取文件名
constexpr const char *get_file_name(const char *path) {
    if (!path) return nullptr;
    std::string_view sv(path);
    auto pos = sv.find_last_of("\\/");
    return (pos == std::string_view::npos) ? path : path + pos + 1;
}

// --- 日志行构建器 (栈上对象) ---
class NanoLogLine {
   public:
    using SupportedTypes = std::tuple<uint8_t, uint16_t, uint32_t, uint64_t, int8_t, int16_t, int32_t, int64_t, float, double, char, const char *, char *>;

    NanoLogLine(LogLevel level, const char *file, const char *func, uint32_t line) : m_bytes_used(0) {
        // 编码头部信息：时间戳, 线程ID, 文件, 函数, 行号, 级别
        encode_raw(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count(),
                   std::this_thread::get_id(),
                   get_file_name(file),
                   func,
                   line,
                   level);
    }

    // 禁止拷贝，允许移动 (虽然主要作为临时对象使用)
    NanoLogLine(const NanoLogLine &) = delete;
    NanoLogLine &operator=(const NanoLogLine &) = delete;
    NanoLogLine(NanoLogLine &&) = default;
    NanoLogLine &operator=(NanoLogLine &&) = default;

    template <typename T>
        requires std::is_arithmetic_v<T>
    NanoLogLine &operator<<(T arg) {
        encode_with_id<T>(arg);
        return *this;
    }

    NanoLogLine &operator<<(const char *arg) {
        if (arg) encode_c_string(arg, std::strlen(arg));
        return *this;
    }

    NanoLogLine &operator<<(char *arg) {
        if (arg) encode_c_string(arg, std::strlen(arg));
        return *this;
    }

    const char *buffer() const { return m_stack_buffer; }
    size_t bytes_used() const { return m_bytes_used; }

    // 静态解码函数：将 buffer 数据格式化到 ostream
    static void stringify(std::ostream &os, char *start, size_t len) {
        char *b = start;
        char *end = b + len;

        // 1. 解码头部 (顺序必须与构造函数 encode_raw 一致)
        auto ts_ns = decode_raw<uint64_t>(b);
        auto tid = decode_raw<std::thread::id>(b);
        auto file = decode_raw<const char *>(b);
        auto func = decode_raw<const char *>(b);
        auto line = decode_raw<uint32_t>(b);
        auto level = decode_raw<LogLevel>(b);

        // 2. 格式化前缀
        auto tp = std::chrono::sys_time<std::chrono::nanoseconds>{std::chrono::nanoseconds{ts_ns}};
        auto formatted_local_tp = std::format("[{:%F %T}]", std::chrono::zoned_time{std::chrono::current_zone(), tp});

        // 3. 输出头部
        static const char *level_strs[] = {"INFO", "WARN", "CRIT"};
        os << formatted_local_tp << '[' << level_strs[static_cast<uint8_t>(level)] << "][" << tid << "][" << file << ':' << func << ':' << line << "] ";

        // 4. 循环解码参数
        while (b < end) {
            uint8_t id = *reinterpret_cast<uint8_t *>(b++);
            b = dispatch_decode(id, b, os);
        }
        os << '\n';
    }

   private:
    size_t m_bytes_used;
    char m_stack_buffer[MAX_LOG_LINE_SIZE];  // 固定大小，极大简化

    template <typename T>
    static constexpr uint8_t get_type_id() {
        return []<size_t... I>(std::index_sequence<I...>) {
            uint8_t index = 0;
            ((std::is_same_v<T, std::tuple_element_t<I, SupportedTypes>> ? index = I : 0), ...);
            return index;
        }(std::make_index_sequence<std::tuple_size_v<SupportedTypes>>{});
    }

    template <typename... Args>
    void encode_raw(Args... args) {
        // 折叠表达式编码，带边界检查
        ((has_space(sizeof(Args)) ? (std::memcpy(curr(), &args, sizeof(Args)), m_bytes_used += sizeof(Args)) : 0), ...);
    }

    template <typename T>
    void encode_with_id(T arg) {
        if (!has_space(sizeof(T) + 1)) return;  // ID + Content
        *reinterpret_cast<uint8_t *>(curr()) = get_type_id<T>();
        m_bytes_used++;
        std::memcpy(curr(), &arg, sizeof(T));
        m_bytes_used += sizeof(T);
    }

    void encode_c_string(const char *arg, size_t len) {
        if (!has_space(len + 2)) return;  // ID + Content + '\0'
        *reinterpret_cast<uint8_t *>(curr()) = get_type_id<char *>();
        m_bytes_used++;
        std::memcpy(curr(), arg, len + 1);
        m_bytes_used += len + 1;
    }

    bool has_space(size_t size) const { return m_bytes_used + size <= MAX_LOG_LINE_SIZE; }
    char *curr() { return &m_stack_buffer[m_bytes_used]; }

    template <typename T>
    static T decode_raw(char *&p) {
        T val;
        std::memcpy(&val, p, sizeof(T));
        p += sizeof(T);
        return val;
    }

    // 解码分发表
    template <size_t I>
    static char *decode_element(char *p, std::ostream &s) {
        using T = std::tuple_element_t<I, SupportedTypes>;
        if constexpr (std::is_same_v<T, char *> || std::is_same_v<T, const char *>) {
            s << p << ' ';
            return p + std::strlen(p) + 1;
        } else {
            T val;
            std::memcpy(&val, p, sizeof(T));
            // s << val;
            s << std::format("{} ", val);  // 解决double的精度问题
            return p + sizeof(T);
        }
    }

    static char *dispatch_decode(uint8_t id, char *b, std::ostream &os) {
        using DecodeFunc = char *(*)(char *, std::ostream &);
        static constexpr auto table = []<size_t... I>(std::index_sequence<I...>) {
            return std::array<DecodeFunc, sizeof...(I)>{&decode_element<I>...};
        }(std::make_index_sequence<std::tuple_size_v<SupportedTypes>>{});
        return table[id](b, os);
    }
};

// --- 文件/控制台写入器 ---
class FileWriter {
   public:
    // 模式 1: 文件日志
    FileWriter(std::string log_dir, std::string log_name, uint32_t roll_mb, uint32_t max_files)
        : m_roll_size(roll_mb * 1024 * 1024), m_max_files(max_files), m_base_path(std::filesystem::path(log_dir) / log_name), m_is_console(false) {
        std::filesystem::create_directories(m_base_path.parent_path());
        roll_file();
    }

    // 模式 2: Console 日志 (默认构造)
    FileWriter() : m_roll_size(0), m_max_files(0), m_is_console(true) {
        m_os = &std::cout;
    }

    void write(char *data, size_t size) {
        if (m_is_console) {
            NanoLogLine::stringify(*m_os, data, size);
            m_os->flush();  // 确保控制台实时输出
        } else {
            // 文件写入逻辑
            NanoLogLine::stringify(*m_os, data, size);
            m_written += size;
            if (m_written >= m_roll_size) roll_file();
        }
    }

   private:
    void roll_file() {
        if (m_ofs && m_ofs->is_open()) {
            m_ofs->flush();
            m_ofs->close();
        }
        // 1. 计算下一个文件编号 (1 到 m_max_files 循环)
        // 逻辑：Log.1.txt -> Log.2.txt -> ... -> Log.N.txt -> 回到 Log.1.txt
        m_file_num = (m_file_num % m_max_files) + 1;
        std::string path = m_base_path.string() + "." + std::to_string(m_file_num) + ".txt";
        m_ofs = std::make_unique<std::ofstream>(path, std::ios::out | std::ios::trunc);
        m_os = m_ofs.get();
        m_written = 0;
    }

    uint32_t m_roll_size = 0, m_max_files = 0, m_file_num = 0;
    size_t m_written = 0;
    std::filesystem::path m_base_path;
    bool m_is_console;
    std::unique_ptr<std::ofstream> m_ofs;
    std::ostream *m_os = nullptr;
};

// anoymous namespace for SPSCVarQueueOPT
namespace {
// 使用 C++20 Concepts 约束回调函数
template <typename T, typename Header>
concept MsgWriter = requires(T t, Header *h) { t(h); };

template <typename T, typename Header>
concept MsgReader = requires(T t, Header *h) { t(h); };

template <uint32_t Bytes>
class SPSCVarQueueOPT {
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

    SPSCVarQueueOPT() = default;

    // 禁止拷贝
    SPSCVarQueueOPT(const SPSCVarQueueOPT &) = delete;
    SPSCVarQueueOPT &operator=(const SPSCVarQueueOPT &) = delete;

    /**
     * @brief 生产者分配空间
     * @return 返回 Header 指针，若空间不足返回 nullptr
     */
    [[nodiscard]] MsgHeader *alloc(uint16_t data_size) {
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
        MsgHeader &current_msg = blk[p.write_idx_cache];

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
    [[nodiscard]] MsgHeader *front() {
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
        MsgHeader *h = alloc(size);
        if (!h) return false;
        writer(h);
        push();
        return true;
    }

    template <MsgReader<MsgHeader> Reader>
    bool tryPop(Reader reader) {
        MsgHeader *h = front();
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
}  // namespace

// --- 核心：TLS + SPSC ---
class NanoLogger;
using TLSSPSCQueue = SPSCVarQueueOPT<THREAD_QUEUE_SIZE>;
inline std::atomic<NanoLogger *> atomic_logger{nullptr};

class ThreadBuffer {
   public:
    ThreadBuffer() { m_queue = std::make_shared<TLSSPSCQueue>(); }
    ~ThreadBuffer();  // 见下方 NanoLogger 定义后的实现

    // Non-blocking push
    void push(const NanoLogLine &logline) {
        if (!m_queue) return;
        size_t len = logline.bytes_used();
        // SPSC alloc 失败返回 nullptr，即队列满直接丢弃 (NonGuaranteed)
        m_queue->tryPush(static_cast<uint16_t>(len), [&](TLSSPSCQueue::MsgHeader *header) {
            // SPSC MsgHeader 之后是数据区
            char *dest = reinterpret_cast<char *>(header) + sizeof(TLSSPSCQueue::MsgHeader);
            std::memcpy(dest, logline.buffer(), len);
        });
    }

    auto get_queue() { return m_queue; }

   private:
    std::shared_ptr<TLSSPSCQueue> m_queue;
};

class NanoLogger {
   public:
    NanoLogger(std::string dir, std::string name, uint32_t roll_mb, uint32_t max_files)
        : m_state(State::INIT), m_writer(dir, name, roll_mb, max_files), m_thread(&NanoLogger::worker, this) {
        m_state.store(State::READY, std::memory_order_release);
    }
    NanoLogger()
        : m_state(State::INIT), m_thread(&NanoLogger::worker, this) {
        m_state.store(State::READY, std::memory_order_release);
    }
    ~NanoLogger() {
        m_state.store(State::SHUTDOWN);
        if (m_thread.joinable()) m_thread.join();
        // 线程停止后再置空全局指针，防止新线程在此时注册
        atomic_logger.store(nullptr, std::memory_order_release);
    }

    void register_buf(std::shared_ptr<TLSSPSCQueue> q) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queues.push_back(std::move(q));
    }

    void unregister_buf(const std::shared_ptr<TLSSPSCQueue> &q) {
        // 这一块可以不实现
        std::lock_guard<std::mutex> lock(m_mutex);
        // 使用 std::erase 移除对应的 shared_ptr
        // 即使移除了，正在执行 poll 的线程因为 snapshot 持有引用，依然安全
        std::erase(m_queues, q);
    }

   private:
    void worker() {
        while (m_state.load(std::memory_order_acquire) == State::INIT)
            std::this_thread::sleep_for(std::chrono::microseconds(50));

        while (m_state.load() == State::READY) poll(false);
        poll(true);  // 退出前最后一次清空
    }

    void poll(bool drain) {
        bool active = false;
        // 复制快照以减小锁粒度
        std::vector<std::shared_ptr<TLSSPSCQueue>> snapshot;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            snapshot = m_queues;  // 拷贝 shared_ptr 增加引用计数，确保内存安全
        }

        for (auto &q : snapshot) {
            while (auto *header = q->front()) {
                active = true;
                char *data = reinterpret_cast<char *>(header) + sizeof(TLSSPSCQueue::MsgHeader);
                m_writer.write(data, header->size - sizeof(TLSSPSCQueue::MsgHeader));
                q->pop();
            }
        }
        if (!active && !drain) std::this_thread::sleep_for(std::chrono::microseconds(50));
    }

    enum class State { INIT,
                       READY,
                       SHUTDOWN };
    std::atomic<State> m_state;
    FileWriter m_writer;
    std::thread m_thread;
    std::mutex m_mutex;
    std::vector<std::shared_ptr<TLSSPSCQueue>> m_queues;
};

// --- 延迟实现的 ThreadBuffer 析构函数 ---
inline ThreadBuffer::~ThreadBuffer() {
    auto *logger = atomic_logger.load(std::memory_order_acquire);
    if (logger) {
        logger->unregister_buf(m_queue);
    }
}

// --- 对外 API 接口 ---
inline std::unique_ptr<NanoLogger> logger_holder;

inline ThreadBuffer &get_tls_buffer() {
    static thread_local ThreadBuffer tb;
    static thread_local bool registered = false;
    auto *logger = atomic_logger.load(std::memory_order_acquire);

    if (logger && !registered) {
        logger->register_buf(tb.get_queue());
        registered = true;
    }
    return tb;
}

inline void initialize(std::string dir, std::string name, uint32_t roll_mb, uint32_t max_files) {
    logger_holder = std::make_unique<NanoLogger>(dir, name, roll_mb, max_files);
    atomic_logger.store(logger_holder.get(), std::memory_order_seq_cst);
}

inline void initialize() {
    logger_holder = std::make_unique<NanoLogger>();
    atomic_logger.store(logger_holder.get(), std::memory_order_seq_cst);
}

inline std::atomic<unsigned int> log_level = {0};
inline void set_log_level(LogLevel level) { log_level.store(static_cast<unsigned int>(level), std::memory_order_release); }
inline bool is_logged(LogLevel level) { return static_cast<unsigned int>(level) >= log_level.load(std::memory_order_relaxed); }

struct NanoLog {
    bool operator==(const NanoLogLine &logline) {
        if (atomic_logger.load(std::memory_order_relaxed)) {
            get_tls_buffer().push(logline);
        }
        return true;
    }
};
}  // namespace nanolog

#define NANO_LOG(LEVEL) nanolog::NanoLog() == nanolog::NanoLogLine(LEVEL, __FILE__, __func__, __LINE__)
#define LOG_INFO nanolog::is_logged(nanolog::LogLevel::INFO) && NANO_LOG(nanolog::LogLevel::INFO)
#define LOG_WARN nanolog::is_logged(nanolog::LogLevel::WARN) && NANO_LOG(nanolog::LogLevel::WARN)
#define LOG_CRIT nanolog::is_logged(nanolog::LogLevel::CRIT) && NANO_LOG(nanolog::LogLevel::CRIT)

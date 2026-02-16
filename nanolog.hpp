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

#include "spsc.hpp"

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
    using SupportedTypes = std::tuple<char, uint32_t, uint64_t, int32_t, int64_t, double, const char *, char *>;

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

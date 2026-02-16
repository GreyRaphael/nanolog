#pragma once
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <iosfwd>
#include <iostream>
#include <memory>
#include <queue>
#include <string>
#include <thread>
#include <tuple>
#include <type_traits>

namespace nanolog {
enum class LogLevel : uint8_t { INFO,
                                WARN,
                                CRIT };

/*
 * Non guaranteed logging. Uses a ring buffer to hold log lines.
 * When the ring gets full, the previous log line in the slot will be dropped.
 * Does not block producer even if the ring buffer is full.
 * ring_buffer_size_mb - LogLines are pushed into a mpsc ring buffer whose size
 * is determined by this parameter. Since each LogLine is 256 bytes,
 * ring_buffer_size = ring_buffer_size_mb * 1024 * 1024 / 256
 */
struct NonGuaranteedLogger {
    NonGuaranteedLogger(uint32_t ring_buffer_size_mb_) : ring_buffer_size_mb(ring_buffer_size_mb_) {}
    uint32_t ring_buffer_size_mb;
};

/*
 * Provides a guarantee log lines will not be dropped.
 */
struct GuaranteedLogger {};

namespace {

// 跨平台获取文件名（仅保留最后一部分）
// 使用 inline 确保安全
constexpr const char *get_file_name(const char *path) {
    if (!path) return nullptr;
    std::string_view sv(path);
    auto pos = sv.find_last_of("\\/");
    return (pos == std::string_view::npos) ? path : path + pos + 1;
}

inline std::thread::id this_thread_id() {
    thread_local const auto id = std::this_thread::get_id();
    return id;
}

template <typename T>
concept CString = std::same_as<std::decay_t<T>, char *> || std::same_as<std::decay_t<T>, const char *>;

}  // anonymous namespace

class NanoLogLine {
   public:
    using SupportedTypes = std::tuple<char, uint32_t, uint64_t, int32_t, int64_t, double, const char *, char *>;

    NanoLogLine(LogLevel level, const char *file, const char *func, uint32_t line)
        : m_bytes_used(0), m_buffer_size(sizeof(m_stack_buffer)) {
        // 使用折叠表达式直接编码头部
        encode_raw(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count(),
                   this_thread_id(), get_file_name(file), func, line, level);
    }

    // 显式允许移动构造
    NanoLogLine(NanoLogLine &&) noexcept = default;
    // 显式允许移动赋值
    NanoLogLine &operator=(NanoLogLine &&) noexcept = default;
    // 显式禁用拷贝
    NanoLogLine(const NanoLogLine &) = delete;
    NanoLogLine &operator=(const NanoLogLine &) = delete;

    // 算术类型重载
    template <typename T>
        requires std::is_arithmetic_v<T>
    NanoLogLine &operator<<(T arg) {
        encode_with_id<T>(arg);
        return *this;
    }

    // C 字符串重载
    NanoLogLine &operator<<(CString auto arg) {
        if (arg) encode_c_string(arg, std::strlen(arg));
        return *this;
    }

    void stringify(std::ostream &os) {
        char *b = !m_heap_buffer ? m_stack_buffer : m_heap_buffer.get();
        char *end = b + m_bytes_used;

        // 1. 解码头部固定信息 (按照构造函数里的 encode_raw 顺序)
        auto ts_ns = decode_raw<uint64_t>(b);
        auto tid = decode_raw<std::thread::id>(b);
        auto file = decode_raw<const char *>(b);
        auto func = decode_raw<const char *>(b);
        auto line = decode_raw<uint32_t>(b);
        auto level = decode_raw<LogLevel>(b);

        // 2. 格式化输出头部 (C++20 风格)
        auto tp = std::chrono::sys_time<std::chrono::nanoseconds>{std::chrono::nanoseconds{ts_ns}};
        auto formatted_local_tp = std::format("[{:%F %T}]", std::chrono::zoned_time{std::chrono::current_zone(), tp});

        os << formatted_local_tp << '[' << level2str(level) << "][" << tid << "][" << file << ':' << func << ':' << line << "] ";

        // 3. 循环解码后续动态参数
        while (b < end) {
            uint8_t id = *reinterpret_cast<uint8_t *>(b++);
            b = dispatch_decode(id, b, os);
        }

        os << '\n';
        if (level >= LogLevel::CRIT) os.flush();
    }

   private:
    // --- 保持不变的内存布局 ---
    size_t m_bytes_used;
    size_t m_buffer_size;
    std::unique_ptr<char[]> m_heap_buffer;
    char m_stack_buffer[256 - 2 * sizeof(size_t) - sizeof(decltype(m_heap_buffer)) - 8];

    // --- 内部优化逻辑 ---

    static constexpr const char *level2str(LogLevel l) {
        switch (l) {
            case LogLevel::INFO:
                return "INFO";
            case LogLevel::WARN:
                return "WARN";
            case LogLevel::CRIT:
                return "CRIT";
            default:
                return "XXXX";
        }
    }

    template <typename T>
    static constexpr uint8_t get_type_id() {
        return []<size_t... I>(std::index_sequence<I...>) {
            uint8_t index = 0;
            ((std::is_same_v<T, std::tuple_element_t<I, SupportedTypes>> ? index = I : 0), ...);
            return index;
        }(std::make_index_sequence<std::tuple_size_v<SupportedTypes>>{});
    }

    char *current_buffer_ptr() {
        return !m_heap_buffer ? &m_stack_buffer[m_bytes_used] : &m_heap_buffer[m_bytes_used];
    }

    template <typename... Args>
    void encode_raw(Args... args) {
        // 使用折叠表达式一次性写入多个参数，无需 resize 检查（头部信息通常在 stack 范围内）
        ((std::memcpy(current_buffer_ptr(), &args, sizeof(Args)), m_bytes_used += sizeof(Args)), ...);
    }

    template <typename T>
    void encode_with_id(T arg) {
        resize_buffer_if_needed(sizeof(T) + 1);
        *reinterpret_cast<uint8_t *>(current_buffer_ptr()) = get_type_id<T>();
        m_bytes_used += 1;
        std::memcpy(current_buffer_ptr(), &arg, sizeof(T));
        m_bytes_used += sizeof(T);
    }

    void encode_c_string(const char *arg, size_t len) {
        resize_buffer_if_needed(len + 2);  // 1字节ID + 字符串内容 + \0
        *reinterpret_cast<uint8_t *>(current_buffer_ptr()) = get_type_id<char *>();
        m_bytes_used += 1;
        std::memcpy(current_buffer_ptr(), arg, len + 1);
        m_bytes_used += len + 1;
    }

    template <typename T>
    T decode_raw(char *&p) {
        T val;
        std::memcpy(&val, p, sizeof(T));
        p += sizeof(T);
        return val;
    }

    // 使用函数指针表替代 switch-case
    template <size_t I>
    static char *decode_element(char *p, std::ostream &s) {
        using T = std::tuple_element_t<I, SupportedTypes>;
        if constexpr (std::is_same_v<T, char *> || std::is_same_v<T, const char *>) {
            s << p;
            return p + std::strlen(p) + 1;
        } else {
            T val;
            std::memcpy(&val, p, sizeof(T));
            s << val;
            return p + sizeof(T);
        }
    }

    char *dispatch_decode(uint8_t id, char *b, std::ostream &os) {
        using DecodeFunc = char *(*)(char *, std::ostream &);

        // 2. 使用一个辅助函数生成数组，避免在函数内部处理复杂的 lambda constexpr
        static constexpr auto table = []<size_t... I>(std::index_sequence<I...>) {
            return std::array<DecodeFunc, sizeof...(I)>{&decode_element<I>...};
        }(std::make_index_sequence<std::tuple_size_v<SupportedTypes>>{});

        return table[id](b, os);
    }

    void resize_buffer_if_needed(size_t additional) {
        if (m_bytes_used + additional <= m_buffer_size) return;
        size_t new_size = std::max(m_buffer_size * 2, m_bytes_used + additional);
        auto *new_ptr = new char[new_size];
        std::memcpy(new_ptr, !m_heap_buffer ? m_stack_buffer : m_heap_buffer.get(), m_bytes_used);
        m_heap_buffer.reset(new_ptr);
        m_buffer_size = new_size;
    }
};

struct BufferBase {
    virtual ~BufferBase() = default;
    virtual void push(NanoLogLine &&logline) = 0;
    virtual bool try_pop(NanoLogLine &logline) = 0;
};

struct SpinLock {
    SpinLock(std::atomic_flag &flag) : m_flag(flag) {
        while (m_flag.test_and_set(std::memory_order_acquire));
    }

    ~SpinLock() {
        m_flag.clear(std::memory_order_release);
    }

   private:
    std::atomic_flag &m_flag;
};

/* Multi Producer Single Consumer Ring Buffer */
class RingBuffer : public BufferBase {
   public:
    struct alignas(64) Item {
        Item()
            : written(0), logline(LogLevel::INFO, nullptr, nullptr, 0) {
        }

        std::atomic_flag flag{};
        char written;
        char padding[256 - sizeof(std::atomic_flag) - sizeof(char) - sizeof(NanoLogLine)];
        NanoLogLine logline;
    };

    RingBuffer(size_t const size)
        : m_size(size), m_ring(static_cast<Item *>(std::malloc(size * sizeof(Item)))), m_write_index(0), m_read_index(0) {
        for (size_t i = 0; i < m_size; ++i) {
            new (&m_ring[i]) Item();
        }
        static_assert(sizeof(Item) == 256, "Unexpected size != 256");
    }

    ~RingBuffer() {
        for (size_t i = 0; i < m_size; ++i) {
            m_ring[i].~Item();
        }
        std::free(m_ring);
    }

    void push(NanoLogLine &&logline) override {
        unsigned int write_index = m_write_index.fetch_add(1, std::memory_order_relaxed) % m_size;
        Item &item = m_ring[write_index];
        SpinLock spinlock(item.flag);
        item.logline = std::move(logline);
        item.written = 1;
    }

    bool try_pop(NanoLogLine &logline) override {
        Item &item = m_ring[m_read_index % m_size];
        SpinLock spinlock(item.flag);
        if (item.written == 1) {
            logline = std::move(item.logline);
            item.written = 0;
            ++m_read_index;
            return true;
        }
        return false;
    }

    RingBuffer(RingBuffer const &) = delete;
    RingBuffer &operator=(RingBuffer const &) = delete;

   private:
    size_t const m_size;
    Item *m_ring;
    std::atomic<unsigned int> m_write_index;
    char pad[64];
    unsigned int m_read_index;
};

class Buffer {
   public:
    struct Item {
        Item(NanoLogLine &&nanologline) : logline(std::move(nanologline)) {}
        char padding[256 - sizeof(NanoLogLine)];
        NanoLogLine logline;
    };

    static constexpr const size_t size = 32768;  // 8MB. Helps reduce memory fragmentation

    Buffer() : m_buffer(static_cast<Item *>(std::malloc(size * sizeof(Item)))) {
        for (size_t i = 0; i <= size; ++i) {
            m_write_state[i].store(0, std::memory_order_relaxed);
        }
        static_assert(sizeof(Item) == 256, "Unexpected size != 256");
    }

    ~Buffer() {
        unsigned int write_count = m_write_state[size].load();
        for (size_t i = 0; i < write_count; ++i) {
            m_buffer[i].~Item();
        }
        std::free(m_buffer);
    }

    // Returns true if we need to switch to next buffer
    bool push(NanoLogLine &&logline, unsigned int const write_index) {
        new (&m_buffer[write_index]) Item(std::move(logline));
        m_write_state[write_index].store(1, std::memory_order_release);
        return m_write_state[size].fetch_add(1, std::memory_order_acquire) + 1 == size;
    }

    bool try_pop(NanoLogLine &logline, unsigned int const read_index) {
        if (m_write_state[read_index].load(std::memory_order_acquire)) {
            Item &item = m_buffer[read_index];
            logline = std::move(item.logline);
            return true;
        }
        return false;
    }

    Buffer(Buffer const &) = delete;
    Buffer &operator=(Buffer const &) = delete;

   private:
    Item *m_buffer;
    std::atomic<unsigned int> m_write_state[size + 1];
};

class QueueBuffer : public BufferBase {
   public:
    QueueBuffer(QueueBuffer const &) = delete;
    QueueBuffer &operator=(QueueBuffer const &) = delete;

    QueueBuffer() : m_current_read_buffer{nullptr}, m_write_index(0), m_read_index(0) {
        setup_next_write_buffer();
    }

    void push(NanoLogLine &&logline) override {
        unsigned int write_index = m_write_index.fetch_add(1, std::memory_order_relaxed);
        if (write_index < Buffer::size) {
            if (m_current_write_buffer.load(std::memory_order_acquire)->push(std::move(logline), write_index)) {
                setup_next_write_buffer();
            }
        } else {
            while (m_write_index.load(std::memory_order_acquire) >= Buffer::size);
            push(std::move(logline));
        }
    }

    bool try_pop(NanoLogLine &logline) override {
        if (m_current_read_buffer == nullptr)
            m_current_read_buffer = get_next_read_buffer();

        Buffer *read_buffer = m_current_read_buffer;

        if (read_buffer == nullptr)
            return false;

        if (bool success = read_buffer->try_pop(logline, m_read_index)) {
            m_read_index++;
            if (m_read_index == Buffer::size) {
                m_read_index = 0;
                m_current_read_buffer = nullptr;
                SpinLock spinlock(m_flag);
                m_buffers.pop();
            }
            return true;
        }

        return false;
    }

   private:
    void setup_next_write_buffer() {
        std::unique_ptr<Buffer> next_write_buffer(new Buffer());
        m_current_write_buffer.store(next_write_buffer.get(), std::memory_order_release);
        SpinLock spinlock(m_flag);
        m_buffers.push(std::move(next_write_buffer));
        m_write_index.store(0, std::memory_order_relaxed);
    }

    Buffer *get_next_read_buffer() {
        SpinLock spinlock(m_flag);
        return m_buffers.empty() ? nullptr : m_buffers.front().get();
    }

   private:
    std::queue<std::unique_ptr<Buffer>> m_buffers;
    std::atomic<Buffer *> m_current_write_buffer;
    Buffer *m_current_read_buffer;
    std::atomic<unsigned int> m_write_index;
    std::atomic_flag m_flag{};
    unsigned int m_read_index;
};

class FileWriter {
   public:
    // 文件模式构造函数
    FileWriter(std::string const &log_directory,
               std::string const &log_file_name,
               uint32_t log_file_roll_size_mb,
               uint32_t max_files)  // 新增：最大保留文件数
        : m_log_file_roll_size_bytes(log_file_roll_size_mb * 1024 * 1024),
          m_base_path(std::filesystem::path(log_directory) / log_file_name),
          m_max_files(max_files),
          m_is_stdout(false) {
        // 确保目录存在
        std::filesystem::create_directories(m_base_path.parent_path());
        roll_file();
    }

    // 新增：std::cout 模式构造函数
    FileWriter()
        : m_log_file_roll_size_bytes(0),
          m_max_files(0),
          m_is_stdout(true) {
        m_os_ptr = &std::cout;
    }

    void write(NanoLogLine &logline) {
        if (m_is_stdout) {
            logline.stringify(*m_os_ptr);
            m_os_ptr->flush();  // 实时刷新屏幕输出
            return;
        }

        // 文件模式逻辑
        // 使用 tellp() 可能会有性能开销，但在滚动逻辑中是必要的
        auto pos = m_os_ptr->tellp();
        logline.stringify(*m_os_ptr);
        m_bytes_written += (m_os_ptr->tellp() - pos);

        if (m_bytes_written >= m_log_file_roll_size_bytes) {
            roll_file();
        }
    }

   private:
    void roll_file() {
        if (m_file_stream && m_file_stream->is_open()) {
            m_file_stream->flush();
            m_file_stream->close();
        }

        // 1. 计算下一个文件编号 (1 到 m_max_files 循环)
        // 逻辑：Log.1.txt -> Log.2.txt -> ... -> Log.N.txt -> 回到 Log.1.txt
        m_file_number = (m_file_number % m_max_files) + 1;

        // 2. 构造文件名
        std::string current_file = m_base_path.string() + "." + std::to_string(m_file_number) + ".txt";

        // 重新打开文件流
        m_file_stream = std::make_unique<std::ofstream>(current_file, std::ofstream::out | std::ofstream::trunc);
        m_os_ptr = m_file_stream.get();  // 更新基类指针指向
        m_bytes_written = 0;
    }

   private:
    bool const m_is_stdout;
    uint32_t m_file_number = 0;
    std::streamoff m_bytes_written = 0;
    uint32_t const m_log_file_roll_size_bytes;
    uint32_t const m_max_files;
    std::filesystem::path const m_base_path;

    std::ostream *m_os_ptr = nullptr;              // 统一的操作指针
    std::unique_ptr<std::ofstream> m_file_stream;  // 仅在文件模式下持有所有权
};

class NanoLogger {
   public:
    NanoLogger(NonGuaranteedLogger ngl, std::string const &log_directory, std::string const &log_file_name, uint32_t log_file_roll_size_mb, uint32_t max_files)
        : m_state(State::INIT), m_buffer_base(new RingBuffer(std::max(1u, ngl.ring_buffer_size_mb) * 1024 * 4)), m_file_writer(log_directory, log_file_name, std::max(1u, log_file_roll_size_mb), max_files), m_thread(&NanoLogger::pop, this) {
        m_state.store(State::READY, std::memory_order_release);
    }

    NanoLogger(GuaranteedLogger gl, std::string const &log_directory, std::string const &log_file_name, uint32_t log_file_roll_size_mb, uint32_t max_files)
        : m_state(State::INIT), m_buffer_base(new QueueBuffer()), m_file_writer(log_directory, log_file_name, std::max(1u, log_file_roll_size_mb), max_files), m_thread(&NanoLogger::pop, this) {
        m_state.store(State::READY, std::memory_order_release);
    }

    NanoLogger()
        : m_state(State::INIT), m_buffer_base(new QueueBuffer()), m_thread(&NanoLogger::pop, this) {
        // : m_state(State::INIT), m_buffer_base(new RingBuffer(8 * 1024 * 1024)), m_thread(&NanoLogger::pop, this) {
        m_state.store(State::READY, std::memory_order_release);
    }

    ~NanoLogger() {
        m_state.store(State::SHUTDOWN);
        m_thread.join();
    }

    void add(NanoLogLine &&logline) {
        m_buffer_base->push(std::move(logline));
    }

    void pop() {
        // Wait for constructor to complete and pull all stores done there to this thread / core.
        while (m_state.load(std::memory_order_acquire) == State::INIT)
            std::this_thread::sleep_for(std::chrono::microseconds(50));

        NanoLogLine logline(LogLevel::INFO, nullptr, nullptr, 0);

        while (m_state.load() == State::READY) {
            if (m_buffer_base->try_pop(logline))
                m_file_writer.write(logline);
            else
                std::this_thread::sleep_for(std::chrono::microseconds(50));
        }

        // Pop and log all remaining entries
        while (m_buffer_base->try_pop(logline)) {
            m_file_writer.write(logline);
        }
    }

   private:
    enum class State {
        INIT,
        READY,
        SHUTDOWN
    };

    std::atomic<State> m_state;
    std::unique_ptr<BufferBase> m_buffer_base;
    FileWriter m_file_writer;
    std::thread m_thread;
};

inline std::unique_ptr<NanoLogger> nanologger;

inline std::atomic<NanoLogger *> atomic_nanologger;

struct NanoLog {
    /*
     * Ideally this should have been operator+=
     * Could not get that to compile, so here we are...
     */
    bool operator==(NanoLogLine &logline) {
        atomic_nanologger.load(std::memory_order_acquire)->add(std::move(logline));
        return true;
    }
};

inline std::atomic<unsigned int> loglevel = {0};

inline void set_log_level(LogLevel level) {
    loglevel.store(static_cast<unsigned int>(level), std::memory_order_release);
}

inline bool is_logged(LogLevel level) {
    return static_cast<unsigned int>(level) >= loglevel.load(std::memory_order_relaxed);
}

/*
 * Ensure initialize() is called prior to any log statements.
 * log_directory - where to create the logs. For example - "/tmp/"
 * log_file_name - root of the file name. For example - "nanolog"
 * This will create log files of the form -
 * /tmp/nanolog.1.txt
 * /tmp/nanolog.2.txt
 * etc.
 * log_file_roll_size_mb - mega bytes after which we roll to next log file.
 */
//	void initialize(GuaranteedLogger gl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb);
//	void initialize(NonGuaranteedLogger ngl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb);
inline void initialize(NonGuaranteedLogger ngl, std::string const &log_directory, std::string const &log_file_name, uint32_t log_file_roll_size_mb, uint32_t max_files) {
    nanologger.reset(new NanoLogger(ngl, log_directory, log_file_name, log_file_roll_size_mb, max_files));
    atomic_nanologger.store(nanologger.get(), std::memory_order_seq_cst);
}

inline void initialize(GuaranteedLogger gl, std::string const &log_directory, std::string const &log_file_name, uint32_t log_file_roll_size_mb, uint32_t max_files) {
    nanologger.reset(new NanoLogger(gl, log_directory, log_file_name, log_file_roll_size_mb, max_files));
    atomic_nanologger.store(nanologger.get(), std::memory_order_seq_cst);
}

inline void initialize() {
    nanologger.reset(new NanoLogger());
    atomic_nanologger.store(nanologger.get(), std::memory_order_seq_cst);
}
}  // namespace nanolog

#define NANO_LOG(LEVEL) nanolog::NanoLog() == nanolog::NanoLogLine(LEVEL, __FILE__, __func__, __LINE__)
#define LOG_INFO nanolog::is_logged(nanolog::LogLevel::INFO) && NANO_LOG(nanolog::LogLevel::INFO)
#define LOG_WARN nanolog::is_logged(nanolog::LogLevel::WARN) && NANO_LOG(nanolog::LogLevel::WARN)
#define LOG_CRIT nanolog::is_logged(nanolog::LogLevel::CRIT) && NANO_LOG(nanolog::LogLevel::CRIT)

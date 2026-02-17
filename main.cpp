#include "nanolog.hpp"

void test_console() {
    nanolog::initialize(10);
    for (auto i = 0; i < 4e4; ++i) {
        LOG_INFO << "hello" << i << "world" << 10.1 * i << 'x';
    }
}

void test_file() {
    nanolog::initialize(
        "log",   // log_directory
        "main",  // log _file_name
        1,       // log_file_roll_size_mb
        3,       // max_files
        10);     // queue sie in mb
    for (auto i = 0; i < 4e4; ++i) {
        LOG_INFO << "hello" << i << "world" << 10.1 * i << 'x';
    }
}

int main() {
    // test_console();
    test_file();
}

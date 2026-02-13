#include "nanolog.hpp"

int main() {
    nanolog::initialize(
        nanolog::GuaranteedLogger(), // Or if you want to use the non guaranteed logger
        "log",            // log_directory
        "main",           // log _file_name
        1,        // log_file_roll_size_mb
        3);                   // max_files
    for (auto i = 0; i < 4e4; ++i) {
        LOG_INFO << "hello" << i;
    }
}
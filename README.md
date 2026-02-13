# header-only c++20 cross-platform nanolog

## features
1. head-only, just use `nanolog.hpp`
2. c++20 support
3. cross-platform: Linux & Windows tested
4. log file rotating

Based on [NanoLog](https://github.com/Iyengar111/NanoLog) and [nanolog](https://github.com/qicosmos/nanolog)

## examples

```cpp
#include "nanolog.hpp"

int main() {
    nanolog::initialize(
        nanolog::GuaranteedLogger(),  // Or if you want to use the non guaranteed logger
        "log",                        // log_directory
        "main",                       // log _file_name
        1,                            // log_file_roll_size_mb
        3);                           // max_files
    for (auto i = 0; i < 4e4; ++i) {
        LOG_INFO << "hello" << i;
    }
}
```

```bash
log/
	main.1.txt
	main.2.txt
	main.3.txt
```

```bash
# main.1.txt sample
[2026-02-13 03:07:53.815312800][INFO][140224859211584][main.cpp:main:11] hello37584
[2026-02-13 03:07:53.815314200][INFO][140224859211584][main.cpp:main:11] hello37585
[2026-02-13 03:07:53.815315300][INFO][140224859211584][main.cpp:main:11] hello37586
[2026-02-13 03:07:53.815316400][INFO][140224859211584][main.cpp:main:11] hello37587
[2026-02-13 03:07:53.815317600][INFO][140224859211584][main.cpp:main:11] hello37588
[2026-02-13 03:07:53.815318700][INFO][140224859211584][main.cpp:main:11] hello37589
[2026-02-13 03:07:53.815319800][INFO][140224859211584][main.cpp:main:11] hello37590
```
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
        "log",   // log_directory
        "main",  // log _file_name
        1,       // log_file_roll_size_mb
        3,       // max_files
        10);     // queue sie in mb
    for (auto i = 0; i < 4e4; ++i) {
        LOG_INFO << "hello" << i << "world" << 10.1 * i << 'x';
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
[2026-02-18 17:28:13.614502200][INFO][140596561446784][main.cpp:test_file:18] hello 31297 world 316099.7 x 
[2026-02-18 17:28:13.614503400][INFO][140596561446784][main.cpp:test_file:18] hello 31298 world 316109.8 x 
[2026-02-18 17:28:13.614504200][INFO][140596561446784][main.cpp:test_file:18] hello 31299 world 316119.89999999997 x 
[2026-02-18 17:28:13.614504900][INFO][140596561446784][main.cpp:test_file:18] hello 31300 world 316130 x 
[2026-02-18 17:28:13.614505600][INFO][140596561446784][main.cpp:test_file:18] hello 31301 world 316140.1 x 
```
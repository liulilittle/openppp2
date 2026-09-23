// 提供 buddy_alloc 单头库(stb 风格)的实现。openppp2 主构建在别处生成；
// bench 独立编译，在此单独生成一次 buddy_malloc/free/embed/arena_free_size。
// 先 include stdafx.h：openppp2 版 buddy_allocator.h 的实现体用了 NULLPTR 宏。
#include <ppp/stdafx.h>
#define BUDDY_ALLOC_IMPLEMENTATION
#include <common/memory/buddy_allocator.h>

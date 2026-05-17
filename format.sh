find kernel/src -type f -name "*.[hc]" ! -name "alloc.c" -exec clang-format -i '{}' \;
find modules -type f -name "*.[hc]" -exec clang-format -i '{}' \;

find kernel -type f -name "*.[hc]" -exec clang-format -i '{}' \;
find modules -type f -name "*.[hc]" -exec clang-format -i '{}' \;

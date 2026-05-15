function c_escape(s, out, i, c) {
    out = "";
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1);
        if (c == "\\") {
            out = out "\\\\";
        } else if (c == "\"") {
            out = out "\\\"";
        } else if (c == "\t") {
            out = out "\\t";
        } else {
            out = out c;
        }
    }
    return out;
}

BEGIN {
    count = 0;
    names_size = 1;
}

$1 ~ /^[0-9a-fA-F]+$/ && $2 !~ /^[Uu]$/ && $3 != "" {
    name = $3;
    if (name ~ /^\$/) {
        next;
    }

    count++;
    addrs[count] = $1;
    types[count] = $2;
    names[count] = name;
    offsets[count] = names_size;
    names_size += length(name) + 1;
    exported[count] = (types[count] ~ /^[A-ZWV]$/ &&
                       types[count] !~ /^[Aa]$/) ? 1 : 0;
    can_describe_ip[count] = (types[count] ~ /^[TtWw]$/) ? 1 : 0;
}

END {
    print "#include <stdint.h>";
    print "typedef struct {";
    print "    uint64_t addr;";
    print "    const char *name;";
    print "    uint8_t type;";
    print "    uint8_t exported;";
    print "    uint8_t can_describe_ip;";
    print "} kernel_builtin_symbol_t;";
    print "";
    print "__attribute__((used, section(\".kallsyms\")))";
    print "const char kallsyms_names[] =";
    print "    \"\\0\"";
    for (i = 1; i <= count; i++) {
        printf("    \"%s\\0\"\n", c_escape(names[i]));
    }
    print "    ;";
    print "";
    print "__attribute__((used, section(\".kallsyms\")))";
    print "const kernel_builtin_symbol_t kallsyms_symbols[] = {";
    for (i = 1; i <= count; i++) {
        printf("    {0x%sULL, kallsyms_names + %u, '%s', %u, %u},\n",
               addrs[i], offsets[i], types[i], exported[i],
               can_describe_ip[i]);
    }
    print "};";
    print "";
    print "__attribute__((used, section(\".kallsyms\")))";
    printf("const uint64_t kallsyms_num = %u;\n", count);
}

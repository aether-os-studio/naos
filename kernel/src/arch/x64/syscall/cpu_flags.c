#include <arch/x64/syscall/cpu_info.h>

// CPU特性标志结构
typedef struct {
    uint32_t leaf;    // CPUID叶子节点
    uint32_t subleaf; // CPUID子叶节点
    uint8_t reg;      // 寄存器: 0=EAX, 1=EBX, 2=ECX, 3=EDX
    uint8_t bit;      // 位位置
    const char *name; // 特性名称
} cpu_feature_t;

// 完整的CPU特性表
static const cpu_feature_t cpu_features[] = {
    // CPUID.1:EDX - 基本特性
    {1, 0, 3, 0, "fpu"},      // 浮点单元
    {1, 0, 3, 1, "vme"},      // 虚拟8086模式扩展
    {1, 0, 3, 2, "de"},       // 调试扩展
    {1, 0, 3, 3, "pse"},      // 页大小扩展
    {1, 0, 3, 4, "tsc"},      // 时间戳计数器
    {1, 0, 3, 5, "msr"},      // 模型特定寄存器
    {1, 0, 3, 6, "pae"},      // 物理地址扩展
    {1, 0, 3, 7, "mce"},      // 机器检查异常
    {1, 0, 3, 8, "cx8"},      // CMPXCHG8B指令
    {1, 0, 3, 9, "apic"},     // APIC
    {1, 0, 3, 11, "sep"},     // SYSENTER/SYSEXIT
    {1, 0, 3, 12, "mtrr"},    // 内存类型范围寄存器
    {1, 0, 3, 13, "pge"},     // 页全局使能
    {1, 0, 3, 14, "mca"},     // 机器检查架构
    {1, 0, 3, 15, "cmov"},    // 条件移动指令
    {1, 0, 3, 16, "pat"},     // 页属性表
    {1, 0, 3, 17, "pse36"},   // 36位页大小扩展
    {1, 0, 3, 18, "pn"},      // 处理器序列号
    {1, 0, 3, 19, "clflush"}, // CLFLUSH指令
    {1, 0, 3, 21, "dts"},     // 调试存储
    {1, 0, 3, 22, "acpi"},    // ACPI支持
    {1, 0, 3, 23, "mmx"},     // MMX技术
    {1, 0, 3, 24, "fxsr"},    // FXSAVE/FXRSTOR指令
    {1, 0, 3, 25, "sse"},     // SSE指令
    {1, 0, 3, 26, "sse2"},    // SSE2指令
    {1, 0, 3, 27, "ss"},      // 自嗅探
    {1, 0, 3, 28, "ht"},      // 超线程
    {1, 0, 3, 29, "tm"},      // 热监控
    {1, 0, 3, 30, "ia64"},    // IA64处理器
    {1, 0, 3, 31, "pbe"},     // 待机断点使能

    // CPUID.1:ECX - 扩展特性
    {1, 0, 2, 0, "sse3"},          // SSE3指令
    {1, 0, 2, 1, "pclmulqdq"},     // PCLMULQDQ指令
    {1, 0, 2, 2, "dtes64"},        // 64位调试存储
    {1, 0, 2, 3, "monitor"},       // MONITOR/MWAIT指令
    {1, 0, 2, 4, "ds_cpl"},        // CPL限定调试存储
    {1, 0, 2, 5, "vmx"},           // 虚拟机扩展
    {1, 0, 2, 6, "smx"},           // 安全模式扩展
    {1, 0, 2, 7, "est"},           // 增强SpeedStep技术
    {1, 0, 2, 8, "tm2"},           // 热监控2
    {1, 0, 2, 9, "ssse3"},         // 补充SSE3指令
    {1, 0, 2, 10, "cnxt_id"},      // L1上下文ID
    {1, 0, 2, 11, "sdbg"},         // Silicon Debug接口
    {1, 0, 2, 12, "fma"},          // 融合乘法加法
    {1, 0, 2, 13, "cx16"},         // CMPXCHG16B指令
    {1, 0, 2, 14, "xtpr"},         // xTPR更新控制
    {1, 0, 2, 15, "pdcm"},         // 性能调试能力MSR
    {1, 0, 2, 17, "pcid"},         // 进程上下文标识符
    {1, 0, 2, 18, "dca"},          // 直接缓存访问
    {1, 0, 2, 19, "sse4_1"},       // SSE4.1指令
    {1, 0, 2, 20, "sse4_2"},       // SSE4.2指令
    {1, 0, 2, 21, "x2apic"},       // x2APIC支持
    {1, 0, 2, 22, "movbe"},        // MOVBE指令
    {1, 0, 2, 23, "popcnt"},       // POPCNT指令
    {1, 0, 2, 24, "tsc_deadline"}, // TSC-Deadline
    {1, 0, 2, 25, "aes"},          // AES指令集
    {1, 0, 2, 26, "xsave"},        // XSAVE/XRSTOR指令
    {1, 0, 2, 27, "osxsave"},      // XSAVE使能
    {1, 0, 2, 28, "avx"},          // AVX指令
    {1, 0, 2, 29, "f16c"},         // 16位浮点转换指令
    {1, 0, 2, 30, "rdrand"},       // RDRAND指令
    {1, 0, 2, 31, "hypervisor"},   // 运行在虚拟机监控器中

    // CPUID.7.0:EBX - 结构化扩展特性
    {7, 0, 1, 0, "fsgsbase"},        // RDFSBASE/RDGSBASE指令
    {7, 0, 1, 1, "tsc_adjust"},      // IA32_TSC_ADJUST MSR
    {7, 0, 1, 2, "sgx"},             // 软件防护扩展
    {7, 0, 1, 3, "bmi1"},            // 位操作指令集1
    {7, 0, 1, 4, "hle"},             // 硬件锁省略
    {7, 0, 1, 5, "avx2"},            // AVX2指令
    {7, 0, 1, 6, "fdp_excptn_only"}, // FPU数据指针仅在异常时更新
    {7, 0, 1, 7, "smep"},            // 监督模式执行保护
    {7, 0, 1, 8, "bmi2"},            // 位操作指令集2
    {7, 0, 1, 9, "erms"},            // 增强REP MOVSB/STOSB
    {7, 0, 1, 10, "invpcid"},        // INVPCID指令
    {7, 0, 1, 11, "rtm"},            // 受限事务内存
    {7, 0, 1, 12, "cqm"},            // 缓存QoS监控
    {7, 0, 1, 13, "fpcsds"},         // 废弃FPU CS和FPU DS
    {7, 0, 1, 14, "mpx"},            // 内存保护扩展
    {7, 0, 1, 15, "rdt_a"},          // 资源目录技术分配
    {7, 0, 1, 16, "avx512f"},        // AVX-512基础
    {7, 0, 1, 17, "avx512dq"},       // AVX-512双字和四字
    {7, 0, 1, 18, "rdseed"},         // RDSEED指令
    {7, 0, 1, 19, "adx"},            // 多精度加法进位扩展
    {7, 0, 1, 20, "smap"},           // 监督模式访问保护
    {7, 0, 1, 21, "avx512ifma"},     // AVX-512整数融合乘法加法
    {7, 0, 1, 22, "pcommit"},        // PCOMMIT指令
    {7, 0, 1, 23, "clflushopt"},     // CLFLUSHOPT指令
    {7, 0, 1, 24, "clwb"},           // CLWB指令
    {7, 0, 1, 25, "intel_pt"},       // Intel处理器跟踪
    {7, 0, 1, 26, "avx512pf"},       // AVX-512预取
    {7, 0, 1, 27, "avx512er"},       // AVX-512指数和倒数
    {7, 0, 1, 28, "avx512cd"},       // AVX-512冲突检测
    {7, 0, 1, 29, "sha_ni"},         // SHA扩展
    {7, 0, 1, 30, "avx512bw"},       // AVX-512字节和字
    {7, 0, 1, 31, "avx512vl"},       // AVX-512向量长度

    // CPUID.7.0:ECX - 更多结构化扩展特性
    {7, 0, 2, 0, "prefetchwt1"},      // PREFETCHWT1指令
    {7, 0, 2, 1, "avx512vbmi"},       // AVX-512向量字节操作指令
    {7, 0, 2, 2, "umip"},             // 用户模式指令防护
    {7, 0, 2, 3, "pku"},              // 保护密钥用户页
    {7, 0, 2, 4, "ospke"},            // 保护密钥使能
    {7, 0, 2, 5, "waitpkg"},          // 定时暂停
    {7, 0, 2, 6, "avx512vbmi2"},      // AVX-512向量字节操作指令2
    {7, 0, 2, 7, "cet_ss"},           // 控制流强制技术影子堆栈
    {7, 0, 2, 8, "gfni"},             // 伽罗瓦域指令
    {7, 0, 2, 9, "vaes"},             // 向量AES指令
    {7, 0, 2, 10, "vpclmulqdq"},      // CLMUL指令集(VEX编码)
    {7, 0, 2, 11, "avx512vnni"},      // AVX-512向量神经网络指令
    {7, 0, 2, 12, "avx512bitalg"},    // AVX-512 BITALG指令
    {7, 0, 2, 14, "avx512vpopcntdq"}, // AVX-512向量人口计数指令
    {7, 0, 2, 16, "la57"},            // 5级分页
    {7, 0, 2, 22, "rdpid"},           // RDPID指令
    {7, 0, 2, 25, "cldemote"},        // 缓存行降级
    {7, 0, 2, 27, "movdiri"},         // MOVDIRI指令
    {7, 0, 2, 28, "movdir64b"},       // MOVDIR64B指令
    {7, 0, 2, 29, "enqcmd"},          // Enqueue Stores
    {7, 0, 2, 30, "sgx_lc"},          // SGX启动配置

    // CPUID.80000001h:EDX - AMD扩展特性
    {0x80000001, 0, 3, 11, "syscall"},  // SYSCALL/SYSRET指令
    {0x80000001, 0, 3, 20, "nx"},       // 执行禁用位
    {0x80000001, 0, 3, 22, "mmxext"},   // AMD MMX扩展
    {0x80000001, 0, 3, 25, "fxsr_opt"}, // FXSAVE/FXRSTOR优化
    {0x80000001, 0, 3, 26, "pdpe1gb"},  // 1GB大页
    {0x80000001, 0, 3, 27, "rdtscp"},   // RDTSCP指令
    {0x80000001, 0, 3, 29, "lm"},       // 长模式(64位)
    {0x80000001, 0, 3, 30, "3dnowext"}, // 3DNow!扩展
    {0x80000001, 0, 3, 31, "3dnow"},    // 3DNow!

    // CPUID.80000001h:ECX - AMD扩展特性
    {0x80000001, 0, 2, 0, "lahf_lm"},       // LAHF/SAHF在64位模式
    {0x80000001, 0, 2, 1, "cmp_legacy"},    // 核心多处理遗留模式
    {0x80000001, 0, 2, 2, "svm"},           // 安全虚拟机
    {0x80000001, 0, 2, 3, "extapic"},       // 扩展APIC空间
    {0x80000001, 0, 2, 4, "cr8_legacy"},    // CR8在32位模式
    {0x80000001, 0, 2, 5, "abm"},           // 高级位操作
    {0x80000001, 0, 2, 6, "sse4a"},         // SSE4a
    {0x80000001, 0, 2, 7, "misalignsse"},   // 错位SSE模式
    {0x80000001, 0, 2, 8, "3dnowprefetch"}, // 3DNow!预取指令
    {0x80000001, 0, 2, 9, "osvw"},          // OS可见工作区
    {0x80000001, 0, 2, 10, "ibs"},          // 指令基础采样
    {0x80000001, 0, 2, 11, "xop"},          // 扩展操作
    {0x80000001, 0, 2, 12, "skinit"},       // SKINIT/STGI指令
    {0x80000001, 0, 2, 13, "wdt"},          // 看门狗定时器
    {0x80000001, 0, 2, 15, "lwp"},          // 轻量级分析
    {0x80000001, 0, 2, 16, "fma4"},         // 4操作数FMA指令
    {0x80000001, 0, 2, 17, "tce"},          // 翻译缓存扩展
    {0x80000001, 0, 2, 19, "nodeid_msr"},   // NodeID MSR
    {0x80000001, 0, 2, 21, "tbm"},          // 尾调用分支预测
    {0x80000001, 0, 2, 22, "topoext"},      // 拓扑扩展
    {0x80000001, 0, 2, 23, "perfctr_core"}, // 核心性能计数器
    {0x80000001, 0, 2, 24, "perfctr_nb"},   // NB性能计数器
    {0x80000001, 0, 2, 26, "bpext"},        // 数据断点扩展
    {0x80000001, 0, 2, 27, "ptsc"},         // 性能时间戳计数器
    {0x80000001, 0, 2, 28, "perfctr_llc"},  // LLC性能计数器
    {0x80000001, 0, 2, 29, "mwaitx"},       // MWAITX/MONITORX指令
};

#define CPU_FEATURES_COUNT (sizeof(cpu_features) / sizeof(cpu_features[0]))

// 获取CPUID信息的结构体
typedef struct {
    uint32_t eax, ebx, ecx, edx;
} cpuid_regs_t;

// 获取特定叶子的CPUID信息
static cpuid_regs_t get_cpuid_info(uint32_t leaf, uint32_t subleaf) {
    cpuid_regs_t regs;
    cpuid_count(leaf, subleaf, &regs.eax, &regs.ebx, &regs.ecx, &regs.edx);
    return regs;
}

// 检查特定特性是否支持
static bool check_cpu_feature(const cpu_feature_t *feature) {
    cpuid_regs_t regs = get_cpuid_info(feature->leaf, feature->subleaf);
    uint32_t reg_value;

    switch (feature->reg) {
    case 0:
        reg_value = regs.eax;
        break;
    case 1:
        reg_value = regs.ebx;
        break;
    case 2:
        reg_value = regs.ecx;
        break;
    case 3:
        reg_value = regs.edx;
        break;
    default:
        return false;
    }

    return (reg_value >> feature->bit) & 1;
}

// 主要的解析函数
void parse_cpu_flags(char *flags_buffer, size_t buffer_size) {
    if (!flags_buffer || buffer_size == 0) {
        return;
    }

    flags_buffer[0] = '\0';
    bool first_flag = true;
    size_t current_pos = 0;

    // 遍历所有特性
    for (size_t i = 0; i < CPU_FEATURES_COUNT; i++) {
        if (check_cpu_feature(&cpu_features[i])) {
            size_t name_len = strlen(cpu_features[i].name);
            size_t needed = name_len + (first_flag ? 0 : 1); // +1 for space

            // 检查缓冲区空间
            if (current_pos + needed >= buffer_size - 1) {
                break; // 缓冲区不足
            }

            // 添加空格分隔符
            if (!first_flag) {
                flags_buffer[current_pos++] = ' ';
            }

            // 添加特性名称
            strcpy(flags_buffer + current_pos, cpu_features[i].name);
            current_pos += name_len;
            first_flag = false;
        }
    }

    flags_buffer[current_pos] = '\0';
}

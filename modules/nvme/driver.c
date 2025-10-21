#include "nvme.h"
#include <libs/aether/block.h>

#define NVME_CSTS_FATAL (1U << 1)
#define NVME_CSTS_RDY (1U << 0)

#define NVME_SQE_OPC_ADMIN_CREATE_IO_SQ 1U
#define NVME_SQE_OPC_ADMIN_CREATE_IO_CQ 5U
#define NVME_SQE_OPC_ADMIN_IDENTIFY 6U

#define NVME_SQE_OPC_IO_WRITE 1U
#define NVME_SQE_OPC_IO_READ 2U

#define NVME_ADMIN_IDENTIFY_CNS_ID_NS 0x00U
#define NVME_ADMIN_IDENTIFY_CNS_ID_CTRL 0x01U
#define NVME_ADMIN_IDENTIFY_CNS_ACT_NSL 0x02U

static inline char *LeadingWhitespace(char *beg, char *end) {
    while (end > beg && *--end <= 0x20) {
        *end = 0;
    }
    while (beg < end && *beg <= 0x20) {
        beg++;
    }
    return beg;
}

void NVMEConfigureQ(NVME_CONTROLLER *ctrl, NVME_QUEUE_COMMON *q, uint32_t idx,
                    uint32_t len) {
    memset(q, 0, sizeof(NVME_QUEUE_COMMON));
    q->DBL = (uint32_t *)(((uint8_t *)ctrl->CAP) + 0x1000 + idx * ctrl->DST);
    q->MSK = len - 1;
}

int NVMEConfigureCQ(NVME_CONTROLLER *ctrl, NVME_COMPLETION_QUEUE *cq,
                    uint32_t idx, uint32_t len) {
    NVMEConfigureQ(ctrl, &cq->COM, idx, len);
    cq->CQE = 0;
    uint64_t phyAddr = 0;
    phyAddr = (uint64_t)alloc_frames(1);
    cq->CQE = (NVME_COMPLETION_QUEUE_ENTRY *)phys_to_virt(phyAddr);
    memset(cq->CQE, 0, 0x1000);
    cq->COM.HAD = 0;
    cq->COM.TAL = 0;
    cq->COM.PHA = 1;
    return 0;
}

int NVMEConfigureSQ(NVME_CONTROLLER *ctrl, NVME_SUBMISSION_QUEUE *sq,
                    uint32_t idx, uint32_t len) {
    NVMEConfigureQ(ctrl, &sq->COM, idx, len);
    uint64_t phyAddr = 0;
    phyAddr = (uint64_t)alloc_frames(1);
    sq->SQE = (NVME_SUBMISSION_QUEUE_ENTRY *)phys_to_virt(phyAddr);
    memset(sq->SQE, 0, 0x1000);
    sq->COM.HAD = 0;
    sq->COM.TAL = 0;
    sq->COM.PHA = 0;
    return 0;
}

int NVMEWaitingRDY(NVME_CONTROLLER *ctrl, uint32_t rdy) {
    uint32_t csts;
    while (rdy != ((csts = ctrl->CAP->CST) & NVME_CSTS_RDY)) {
        arch_pause();
    }
    return 0;
}

NVME_COMPLETION_QUEUE_ENTRY NVMEWaitingCMD(NVME_SUBMISSION_QUEUE *sq,
                                           NVME_SUBMISSION_QUEUE_ENTRY *e) {
    NVME_COMPLETION_QUEUE_ENTRY errcqe;
    memset(&errcqe, 0xFF, sizeof(NVME_COMPLETION_QUEUE_ENTRY));

    if (((sq->COM.TAL + 1) % (sq->COM.MSK + 1ULL)) == sq->COM.HAD) {
        printk("SUBMISSION QUEUE IS FULL\n");
        return errcqe;
    }

    // Commit
    NVME_SUBMISSION_QUEUE_ENTRY *sqe = sq->SQE + sq->COM.TAL;
    memcpy(sqe, e, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
    sqe->CDW0 |= (uint32_t)sq->COM.TAL << 16;

    // Doorbell
    sq->COM.TAL++;
    sq->COM.TAL %= (sq->COM.MSK + 1ULL);
    sq->COM.DBL[0] = (uint32_t)sq->COM.TAL;

    // Check completion
    NVME_COMPLETION_QUEUE *cq = sq->ICQ;
    while ((cq->CQE[cq->COM.HAD].STS & 0x1) != cq->COM.PHA) {
        arch_pause();
    }

    // Consume CQE
    NVME_COMPLETION_QUEUE_ENTRY *cqe = cq->CQE + cq->COM.HAD;
    uint16_t cqNextHAD = (cq->COM.HAD + 1) % (cq->COM.MSK + 1ULL);
    if (cqNextHAD < cq->COM.HAD) {
        cq->COM.PHA ^= 1;
    }
    cq->COM.HAD = cqNextHAD;

    if (cqe->QHD != sq->COM.HAD) {
        sq->COM.HAD = cqe->QHD;
    }
    // Doorbell
    cq->COM.DBL[0] = (uint32_t)cq->COM.HAD;
    return *cqe;
}

void nvme_rwfail(uint16_t status) {
    printk("Status: %#010lx, status code: %#010lx, status code type: %#010lx\n",
           status, status & 0xFF, (status >> 8) & 0x7);
}

// 使用预分配的PRP列表构建当前传输的PRP
bool BuildPRPListFromPreallocated(void *vaddr, uint64_t size,
                                  NVME_PRP_LIST *prpList) {
    uint64_t vaddrStart = (uint64_t)vaddr;
    uint64_t vaddrEnd = vaddrStart + size;
    uint64_t pageMask = DEFAULT_PAGE_SIZE - 1;

    uint64_t firstPage = vaddrStart & ~pageMask;
    uint64_t lastPage = (vaddrEnd - 1) & ~pageMask;
    uint32_t pageCount = ((lastPage - firstPage) / DEFAULT_PAGE_SIZE) + 1;

    if (pageCount <= 2) {
        prpList->prp1 =
            translate_address(get_current_page_dir(false), vaddrStart);
        if (pageCount == 1) {
            prpList->prp2 = 0;
        } else {
            prpList->prp2 = translate_address(get_current_page_dir(false),
                                              firstPage + DEFAULT_PAGE_SIZE);
        }
        return true;
    }

    // 使用预分配的PRP数组
    uint32_t prpEntries = pageCount - 1;
    if (!prpList->A) {
        printk("PRP array not preallocated\n");
        return false;
    }

    uint64_t *prpArray = (uint64_t *)prpList->A;
    uint64_t currentPage = translate_address(get_current_page_dir(false),
                                             firstPage + DEFAULT_PAGE_SIZE);
    for (uint32_t i = 0; i < prpEntries; i++) {
        prpArray[i] = currentPage;
        currentPage += DEFAULT_PAGE_SIZE;
    }

    prpList->prp1 = translate_address(get_current_page_dir(false), vaddrStart);
    prpList->prp2 =
        translate_address(get_current_page_dir(false), (uint64_t)prpArray);

    return true;
}

// 为namespace预分配PRP列表
bool AllocatePRPList(NVME_NAMESPACE *ns) {
    // 计算最大传输需要的PRP数组大小
    uint64_t maxTransferSize;
    if (ns->MXRS != (uint32_t)-1) {
        maxTransferSize = ns->MXRS * ns->BSZ;
    } else {
        // 如果没有限制，使用一个合理的最大值 (例如 2MB)
        maxTransferSize = 2 * 1024 * 1024;
    }

    // 计算最大页数
    uint32_t maxPages =
        (maxTransferSize + DEFAULT_PAGE_SIZE - 1) / DEFAULT_PAGE_SIZE + 1;

    // 如果只需要1-2页，不需要额外的PRP数组
    if (maxPages <= 2) {
        ns->PRP.A = NULL;
        ns->PRP.S = 0;
        ns->PRP.UPRP = false;
        return true;
    }

    // 分配PRP数组 (需要 maxPages-1 个条目)
    uint32_t prpEntries = maxPages - 1;
    uint64_t prpArraySize = prpEntries * sizeof(uint64_t);

    uint64_t *prpArray = (uint64_t *)alloc_frames_bytes(prpArraySize);
    if (!prpArray) {
        printk("Failed to allocate PRP array\n");
        return false;
    }

    ns->PRP.A = prpArray;
    ns->PRP.S = prpArraySize;
    ns->PRP.UPRP = true;

    return true;
}

// 释放namespace的PRP列表
void FreePRPListNamespace(NVME_NAMESPACE *ns) {
    if (ns->PRP.A) {
        free_frames_bytes(ns->PRP.A, ns->PRP.S);
        ns->PRP.A = NULL;
        ns->PRP.S = 0;
    }
}

spinlock_t nvme_transfer_lock = {0};

uint32_t NVMETransfer(NVME_NAMESPACE *ns, void *buf, uint64_t lba,
                      uint32_t count, uint32_t write) {
    if (!count || !ns || !buf)
        return 0;

    if (lba + count > ns->NLBA) {
        printk("NVME: LBA out of range (lba=%llu, count=%u, max=%llu)\n", lba,
               count, ns->NLBA);
        return 0;
    }

    spin_lock(&nvme_transfer_lock);

    uint32_t transferred = 0;
    uint8_t *currentBuf = (uint8_t *)buf;
    uint64_t currentLBA = lba;

    while (count > 0) {
        uint32_t chunk = count;
        if (ns->MXRS != (uint32_t)-1 && chunk > ns->MXRS) {
            chunk = ns->MXRS;
        }

        uint64_t size = chunk * ns->BSZ;

        // 使用预分配的PRP列表
        if (!BuildPRPListFromPreallocated(currentBuf, size, &ns->PRP)) {
            printk("NVME: Failed to build PRP list\n");
            spin_unlock(&nvme_transfer_lock);
            return transferred;
        }

        NVME_SUBMISSION_QUEUE_ENTRY sqe;
        memset(&sqe, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
        sqe.CDW0 = write ? NVME_SQE_OPC_IO_WRITE : NVME_SQE_OPC_IO_READ;
        sqe.NSID = ns->NSID;
        sqe.CDWA = (uint32_t)(currentLBA & 0xFFFFFFFF);
        sqe.CDWB = (uint32_t)(currentLBA >> 32);
        sqe.CDWC = (1UL << 31) | ((chunk - 1) & 0xFFFF);

        sqe.DATA[0] = ns->PRP.prp1;
        sqe.DATA[1] = ns->PRP.prp2;

        NVME_COMPLETION_QUEUE_ENTRY cqe = NVMEWaitingCMD(&ns->CTRL->ISQ, &sqe);
        if ((cqe.STS >> 1) & 0xFF) {
            nvme_rwfail(cqe.STS);
            spin_unlock(&nvme_transfer_lock);
            return transferred;
        }

        currentBuf += size;
        currentLBA += chunk;
        transferred += chunk;
        count -= chunk;
    }

    spin_unlock(&nvme_transfer_lock);

    return transferred;
}

void failed_nvme(NVME_CONTROLLER *ctrl) {
    if (ctrl->ICQ.CQE) {
        free_frames(virt_to_phys((uint64_t)ctrl->ICQ.CQE), 1);
    }
    if (ctrl->ISQ.SQE) {
        free_frames(virt_to_phys((uint64_t)ctrl->ISQ.SQE), 1);
    }
    if (ctrl->ACQ.CQE) {
        free_frames(virt_to_phys((uint64_t)ctrl->ACQ.CQE), 1);
    }
    if (ctrl->ASQ.SQE) {
        free_frames(virt_to_phys((uint64_t)ctrl->ASQ.SQE), 1);
    }
}

void failed_namespace(NVME_IDENTIFY_NAMESPACE *identifyNS) {
    free_frames(virt_to_phys((uint64_t)identifyNS), 1);
}

uint64_t nvme_read(void *data, uint64_t lba, void *buffer, uint64_t bytes) {
    uint64_t ret =
        NVMETransfer((NVME_NAMESPACE *)data, buffer, lba, bytes, false);
    return ret;
}

uint64_t nvme_write(void *data, uint64_t lba, void *buffer, uint64_t bytes) {
    uint64_t ret =
        NVMETransfer((NVME_NAMESPACE *)data, buffer, lba, bytes, true);
    return ret;
}

NVME_CONTROLLER *nvme_driver_init(uint64_t bar0, uint64_t bar_size) {
    NVME_CAPABILITY *cap = (NVME_CAPABILITY *)phys_to_virt(bar0);
    map_page_range(get_current_page_dir(false), (uint64_t)cap, bar0, bar_size,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE |
                       PT_FLAG_DEVICE);

    if (!((cap->CAP >> 37) & 1)) {
        printk("NVME CONTROLLER DOES NOT SUPPORT NVME COMMAND SET\n");
        return NULL;
    }

    NVME_CONTROLLER *ctrl = (NVME_CONTROLLER *)malloc(sizeof(NVME_CONTROLLER));
    memset(ctrl, 0, sizeof(NVME_CONTROLLER));
    ctrl->CAP = cap;
    ctrl->WTO = 500 * ((cap->CAP >> 24) & 0xFF);

    // RST controller
    ctrl->CAP->CC = 0;
    if (NVMEWaitingRDY(ctrl, 0)) {
        printk("NVME FATAL ERROR DURING CONTROLLER SHUTDOWN\n");
        failed_nvme(ctrl);
        return NULL;
    }
    ctrl->DST = 4ULL << ((cap->CAP >> 32) & 0xF);

    int rc = NVMEConfigureCQ(ctrl, &ctrl->ACQ, 1,
                             0x1000 / sizeof(NVME_COMPLETION_QUEUE_ENTRY));
    if (rc) {
        failed_nvme(ctrl);
        return NULL;
    }

    rc = NVMEConfigureSQ(ctrl, &ctrl->ASQ, 0,
                         0x1000 / sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
    if (rc) {
        failed_nvme(ctrl);
        return NULL;
    }
    ctrl->ASQ.ICQ = &ctrl->ACQ;

    ctrl->CAP->AQA = ((uint32_t)ctrl->ACQ.COM.MSK << 16) | ctrl->ASQ.COM.MSK;
    ctrl->CAP->ASQ = virt_to_phys((uint64_t)ctrl->ASQ.SQE);
    ctrl->CAP->ACQ = virt_to_phys((uint64_t)ctrl->ACQ.CQE);

    ctrl->CAP->CC = 1 | (4 << 20) | (6 << 16);
    if (NVMEWaitingRDY(ctrl, 1)) {
        printk("NVME FATAL ERROR DURING CONTROLLER ENABLING");
        failed_nvme(ctrl);
        return NULL;
    }

    /* The admin queue is set up and the controller is ready. Let's figure out
       what namespaces we have. */
    // Identify Controller
    NVME_IDENTIFY_CONTROLLER *identify = 0;
    identify =
        (NVME_IDENTIFY_CONTROLLER *)alloc_frames_bytes(DEFAULT_PAGE_SIZE);
    memset(identify, 0, 0x1000);

    NVME_SUBMISSION_QUEUE_ENTRY sqe;
    memset(&sqe, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
    sqe.CDW0 = NVME_SQE_OPC_ADMIN_IDENTIFY;
    sqe.META = 0;
    sqe.DATA[0] =
        translate_address(get_current_page_dir(false), (uint64_t)identify);
    sqe.DATA[1] = 0;
    sqe.NSID = 0;
    sqe.CDWA = NVME_ADMIN_IDENTIFY_CNS_ID_CTRL;
    NVME_COMPLETION_QUEUE_ENTRY cqe = NVMEWaitingCMD(&ctrl->ASQ, &sqe);
    if ((cqe.STS >> 1) & 0xFF) {
        printk("CANNOT IDENTIFY NVME CONTROLLER\n");
        failed_nvme(ctrl);
        return NULL;
    }

    char buf[41];
    memcpy(buf, identify->SERN, sizeof(identify->SERN));
    buf[sizeof(identify->SERN)] = 0;
    char *serialN = LeadingWhitespace(buf, buf + sizeof(identify->SERN));
    memcpy(ctrl->SER, serialN, strlen(serialN));

    memcpy(buf, identify->MODN, sizeof(identify->MODN));
    buf[sizeof(identify->MODN)] = 0;
    serialN = LeadingWhitespace(buf, buf + sizeof(identify->MODN));
    memcpy(ctrl->MOD, serialN, strlen(serialN));

    ctrl->NSC = identify->NNAM;
    uint8_t mdts = identify->MDTS;
    free_frames_bytes(identify, DEFAULT_PAGE_SIZE);

    if (ctrl->NSC == 0) {
        printk("NO NAMESPACE\n");
        failed_nvme(ctrl);
        return NULL;
    }

    // Create I/O Queue
    // Create I/O CQ
    {
        uint32_t qidx = 3;
        uint32_t entryCount = 1 + (ctrl->CAP->CAP & 0xFFFF);
        if (entryCount > 0x1000 / sizeof(NVME_COMPLETION_QUEUE_ENTRY))
            entryCount = 0x1000 / sizeof(NVME_COMPLETION_QUEUE_ENTRY);
        if (NVMEConfigureCQ(ctrl, &ctrl->ICQ, qidx, entryCount)) {
            printk("CANNOT INIT I/O CQ\n");
            failed_nvme(ctrl);
            return NULL;
        }
        NVME_SUBMISSION_QUEUE_ENTRY ccq;
        memset(&ccq, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
        ccq.CDW0 = NVME_SQE_OPC_ADMIN_CREATE_IO_CQ;
        ccq.META = 0;
        ccq.DATA[0] = virt_to_phys((uint64_t)ctrl->ICQ.CQE);
        ccq.DATA[1] = 0;
        ccq.CDWA = ((uint32_t)ctrl->ICQ.COM.MSK << 16) | (qidx >> 1);
        ccq.CDWB = 1;

        cqe = NVMEWaitingCMD(&ctrl->ASQ, &ccq);
        if ((cqe.STS >> 1) & 0xFF) {
            printk("CANNOT CREATE I/O CQ\n");
            failed_nvme(ctrl);
            return NULL;
        }
    }

    // Create I/O SQ
    {
        uint32_t qidx = 2;
        uint32_t entryCount = 1 + (ctrl->CAP->CAP & 0xFFFF);
        if (entryCount > 0x1000 / sizeof(NVME_SUBMISSION_QUEUE_ENTRY))
            entryCount = 0x1000 / sizeof(NVME_SUBMISSION_QUEUE_ENTRY);
        if (NVMEConfigureSQ(ctrl, &ctrl->ISQ, qidx, entryCount)) {
            printk("CANNOT INIT I/O SQ\n");
            failed_nvme(ctrl);
            return NULL;
        }
        NVME_SUBMISSION_QUEUE_ENTRY csq;
        memset(&csq, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
        csq.CDW0 = NVME_SQE_OPC_ADMIN_CREATE_IO_SQ;
        csq.META = 0;
        csq.DATA[0] = virt_to_phys((uint64_t)ctrl->ISQ.SQE);
        csq.DATA[1] = 0;
        csq.CDWA = ((uint32_t)ctrl->ISQ.COM.MSK << 16) | (qidx >> 1);
        csq.CDWB = ((qidx >> 1) << 16) | 1;

        cqe = NVMEWaitingCMD(&ctrl->ASQ, &csq);
        if ((cqe.STS >> 1) & 0xFF) {
            printk("CANNOT CREATE I/O SQ");
            failed_nvme(ctrl);
            return NULL;
        }
        ctrl->ISQ.ICQ = &ctrl->ICQ;
    }

    uint32_t nsidx = 0;

    // Probe Namespace
    uint32_t nsid = nsidx + 1;

    NVME_IDENTIFY_NAMESPACE *identifyNS =
        (NVME_IDENTIFY_NAMESPACE *)alloc_frames_bytes(DEFAULT_PAGE_SIZE);
    memset(identifyNS, 0, 0x1000);

    memset(&sqe, 0, sizeof(NVME_SUBMISSION_QUEUE_ENTRY));
    sqe.CDW0 = NVME_SQE_OPC_ADMIN_IDENTIFY;
    sqe.META = 0;
    sqe.DATA[0] =
        translate_address(get_current_page_dir(false), (uint64_t)identifyNS);
    sqe.DATA[1] = 0;
    sqe.NSID = nsid;
    sqe.CDWA = NVME_ADMIN_IDENTIFY_CNS_ID_NS;
    cqe = NVMEWaitingCMD(&ctrl->ASQ, &sqe);
    if ((cqe.STS >> 1) & 0xFF) {
        printk("CANNOT IDENTIFY NAMESPACE\n");
        failed_namespace(identifyNS);
        return NULL;
    }

    uint8_t currentLBAFormat = identifyNS->FLBA & 0xF;
    if (currentLBAFormat > identifyNS->NLBA) {
        printk("Current LBA Format error\n");
        failed_namespace(identifyNS);
        return NULL;
    }

    if (!identifyNS->SIZE) {
        printk("Invalid namespace size\n");
        failed_namespace(identifyNS);
        return NULL;
    }

    NVME_NAMESPACE *ns = (NVME_NAMESPACE *)malloc(sizeof(NVME_NAMESPACE));
    memset(ns, 0, sizeof(NVME_NAMESPACE));
    ns->CTRL = ctrl;
    ns->NSID = nsid;
    ns->NLBA = identifyNS->SIZE;

    NVME_LOGICAL_BLOCK_ADDRESS *fmt = identifyNS->LBAF + currentLBAFormat;

    ns->BSZ = 1ULL << fmt->DS;
    ns->META = fmt->MS;
    if (ns->BSZ > 0x1000) {
        printk("BLOCK SIZE > 0x1000 !!!\n");
        failed_namespace(identifyNS);
        free(ns);
        return NULL;
    }

    if (mdts) {
        ns->MXRS = ((1ULL << mdts) * 0x1000) / ns->BSZ;
    } else {
        ns->MXRS = -1;
    }

    if (!AllocatePRPList(ns)) {
        printk("Failed to allocate PRP list for namespace\n");
        failed_namespace(identifyNS);
        free(ns);
        return NULL;
    }

    regist_blkdev((char *)"nvme", ns, ns->BSZ, ns->NLBA * ns->BSZ,
                  ns->MXRS * ns->BSZ, nvme_read, nvme_write);

    return ctrl;
}

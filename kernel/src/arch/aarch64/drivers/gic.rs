use acpi::madt::GiccEntry;
use arm_gic::{
    IntId,
    gicv2::{GicV2, registers::Gicc},
    gicv3::{GicV3, registers::GicrSgi},
};
use spin::{Lazy, Mutex};

use crate::{
    arch::acpi::ACPI,
    mm::phys_to_virt,
    rust::bindings::bindings::{
        DEFAULT_PAGE_SIZE, PT_FLAG_R, PT_FLAG_W, cpu_count, get_current_page_dir, map_page_range,
    },
};

pub struct GicController<'a> {
    gicc: Option<GiccEntry>,
    v2: Option<GicV2<'a>>,
    v3: Option<GicV3<'a>>,
    use_v3: bool,
}

impl<'a> GicController<'a> {
    pub fn new() -> GicController<'a> {
        if let Some(gicr) = ACPI.gicr {
            let gicd = ACPI.gicd.unwrap();

            let virt = phys_to_virt(gicd.physical_base_address as usize);

            unsafe {
                map_page_range(
                    get_current_page_dir(false),
                    virt as u64,
                    gicd.physical_base_address,
                    0x10000,
                    PT_FLAG_R as u64 | PT_FLAG_W as u64,
                );
            }

            let gicr_virt = phys_to_virt(gicr.discovery_range_base_address as usize);

            unsafe {
                map_page_range(
                    get_current_page_dir(false),
                    gicr_virt as u64,
                    gicr.discovery_range_base_address as u64,
                    0x20000 * (cpu_count + 1),
                    PT_FLAG_R as u64 | PT_FLAG_W as u64,
                );
            }

            let gicv3 = unsafe {
                GicV3::new(
                    virt as *mut arm_gic::gicv3::registers::Gicd,
                    gicr_virt as *mut GicrSgi,
                    cpu_count as usize,
                    false,
                )
            };

            GicController {
                gicc: None,
                v2: None,
                v3: Some(gicv3),
                use_v3: true,
            }
        } else {
            let gicd = ACPI.gicd.unwrap();

            let virt = phys_to_virt(gicd.physical_base_address as usize);

            unsafe {
                map_page_range(
                    get_current_page_dir(false),
                    virt as u64,
                    gicd.physical_base_address,
                    0x10000,
                    PT_FLAG_R as u64 | PT_FLAG_W as u64,
                );
            }

            let gicc = ACPI.gicc.unwrap();

            let gicc_virt = phys_to_virt(gicc.gic_registers_address as usize);
            unsafe {
                map_page_range(
                    get_current_page_dir(false),
                    gicc_virt as u64,
                    gicc.gic_registers_address as u64,
                    0x10000,
                    PT_FLAG_R as u64 | PT_FLAG_W as u64,
                );
            }

            let gicv2 = unsafe {
                GicV2::new(
                    virt as *mut arm_gic::gicv2::registers::Gicd,
                    gicc_virt as *mut Gicc,
                )
            };

            GicController {
                gicc: Some(gicc),
                v2: Some(gicv2),
                v3: None,
                use_v3: false,
            }
        }
    }

    pub fn init_cpu(&mut self, cpu: usize) {
        if self.use_v3 {
            if let Some(gicv3) = &mut self.v3 {
                gicv3.setup(cpu);
            }
        } else {
            if let Some(gicv2) = &mut self.v2 {
                gicv2.setup();
            }
        }
    }

    pub fn enable_interrupt(&mut self, intid: u32) {
        if self.use_v3 {
            if let Some(gicv3) = &mut self.v3 {
                // gicv3.enable_interrupt(IntId::spi(intid), None, true);
                // todo
                gicv3.enable_all_interrupts(true);
            }
        } else {
            if let Some(gicv2) = &mut self.v2 {
                // gicv2.enable_interrupt(IntId::spi(intid), true).unwrap();
                // todo
                gicv2.enable_all_interrupts(true);
            }
        }
    }

    pub fn eoi(&mut self, intid: u32) {
        if self.use_v3 {
            if let Some(gicv3) = &mut self.v3 {
                unsafe {
                    core::arch::asm!(
                        "msr ICC_EOIR1_EL1, {0:x}", in(reg) intid
                    );
                }
            }
        } else {
            if let Some(gicv2) = &mut self.v2 {
                // todo
                gicv2.end_interrupt(IntId::spi(intid));
            }
        }
    }

    pub fn get_current_irq(&mut self) -> u32 {
        if self.use_v3 {
            let intid: u32;
            unsafe {
                core::arch::asm!("mrs {0:x}, ICC_IAR1_EL1", out(reg) intid);
            }
            intid
        } else {
            let iar = unsafe {
                (self.gicc.unwrap().gic_registers_address as *mut u32)
                    .wrapping_add(3)
                    .read()
            };

            iar as u32
        }
    }
}

pub static GIC: Lazy<Mutex<GicController<'_>>> = Lazy::new(|| Mutex::new(GicController::new()));

#[unsafe(no_mangle)]
extern "C" fn gic_init() {
    GIC.lock().init_cpu(0);
}

#[unsafe(no_mangle)]
extern "C" fn gic_init_percpu(cpu_id: usize) {
    GIC.lock().init_cpu(cpu_id);
}

#[unsafe(no_mangle)]
extern "C" fn get_current_irq() -> u32 {
    GIC.lock().get_current_irq()
}

#[unsafe(no_mangle)]
extern "C" fn gic_enable_interrupt(irq: u32) {
    GIC.lock().enable_interrupt(irq)
}

#[unsafe(no_mangle)]
extern "C" fn gic_send_eoi(irq: u32) {
    GIC.lock().eoi(irq)
}

#[unsafe(no_mangle)]
extern "C" fn timer_init_percpu() {
    unsafe {
        core::arch::asm!("msr cntp_tval_el0, {0:x}", in(reg) 1_000_000);
        core::arch::asm!("msr cntp_ctl_el0, {0:x}", in(reg) 1);

        GIC.lock().enable_interrupt(30);
    }
}

// 获取系统计时器的当前值
pub fn read_cntvct() -> u64 {
    let cntvct: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) cntvct);
    }
    cntvct
}

// 获取计时器频率(Hz)
pub fn read_cntfrq() -> u64 {
    let cntfrq: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) cntfrq);
    }
    cntfrq
}

// 获取纳秒级时间
#[unsafe(no_mangle)]
pub extern "C" fn nanoTime() -> u64 {
    let ticks = read_cntvct();
    let freq = read_cntfrq();

    let ns = (ticks as u128) * 1_000_000_000 / (freq as u128);

    ns as u64
}

KM_NAME := nvidia_open

export NVIDIA_OPEN_ROOT := $(CURDIR)
INSTALL_BASE_DIR := $(PROJECT_ROOT)/nvidia-open-install-dir

override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)
MODULE_LINKER := $(CC)
MODULE_EXTRA_DEPS := nvidia-open-install-dir
MODULE_LINK_LIBS = $(PROJECT_ROOT)/libgcc_$(ARCH).a $(shell find $(INSTALL_BASE_DIR)/usr/lib/ -name libnvidia-open.a) $(shell find $(INSTALL_BASE_DIR)/usr/lib/ -name libnvidia-open-modeset.a)

override CFLAGS += -DNVRM -D__managarm__
MODULE_INCLUDE_DIRS += \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/arch/nvalloc/unix/include \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/sdk/nvidia/inc/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/inc/kernel/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/arch/nvalloc/common/inc/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/os-interface/include/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/kapi/interface/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/inc/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/unix/common/inc/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/interface/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/kapi/include/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/unix/common/utils/interface/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/include/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/unix/nvidia-push/interface/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/common/modeset/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/nvlink/interface/ \
	$(INSTALL_BASE_DIR)/usr/include/nvidia-open/interface/

nvidia-open-install-dir:
	sh build_nvidia_open.sh

include $(PROJECT_ROOT)/modules/build/module.mk

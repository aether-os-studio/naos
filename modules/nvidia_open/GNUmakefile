KM_NAME := nvidia_open

export NVIDIA_OPEN_ROOT := $(shell pwd)

override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix ../../obj-modules-$(ARCH)/$(KM_NAME)/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))

INSTALL_BASE_DIR := $(NVIDIA_OPEN_ROOT)/../../nvidia-open-install-dir

override CFLAGS += -I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/arch/nvalloc/unix/include \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/sdk/nvidia/inc/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/inc/kernel/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/arch/nvalloc/common/inc/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/os-interface/include/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/kapi/interface/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/inc/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/unix/common/inc/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/interface/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/kapi/include/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/unix/common/utils/interface/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/include/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/unix/nvidia-push/interface/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open-modeset/common/modeset/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/common/nvlink/interface/ \
					-I$(INSTALL_BASE_DIR)/usr/include/nvidia-open/interface/ \
					-DNVRM -D__managarm__

all: $(OBJ)
	$(CC) $(CFLAGS) -shared $(OBJ) $(PROJECT_ROOT)/libgcc_$(ARCH).a $(shell find $(INSTALL_BASE_DIR)/usr/lib/ -name libnvidia-open.a) $(shell find $(INSTALL_BASE_DIR)/usr/lib/ -name libnvidia-open-modeset.a) -o ../../modules-$(ARCH)/$(KM_NAME).ko

nvidia-open-install-dir:
	sh build_nvidia_open.sh

# Compilation rules for *.c files.
../../obj-modules-$(ARCH)/$(KM_NAME)/%.c.o: %.c nvidia-open-install-dir GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) -I$(shell pwd)/ -c $< -o $@

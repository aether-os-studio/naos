KM_NAME := linux_abi

override SRCFILES := $(shell find . -name "*.[Sc]" | LC_ALL=C sort)
MODULE_LINK_LIBS := $(PROJECT_ROOT)/libgcc_$(ARCH).a

include $(PROJECT_ROOT)/modules/build/module.mk

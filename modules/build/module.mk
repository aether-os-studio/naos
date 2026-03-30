MODULE_DIR ?= $(CURDIR)
MODULE_OBJ_DIR ?= $(PROJECT_ROOT)/obj-modules-$(ARCH)/$(KM_NAME)
MODULE_OUT_DIR ?= $(PROJECT_ROOT)/modules-$(ARCH)
MODULE_OUTPUT ?= $(MODULE_OUT_DIR)/$(KM_NAME).ko
MODULE_KIND ?= ko
MODULE_AR ?= ar
MODULE_LINKER ?= $(LD)
MODULE_INCLUDE_DIRS ?=
MODULE_LINK_LIBS ?=
MODULE_EXTRA_DEPS ?=
MODULE_OBJ_DEPS ?= $(MODULE_EXTRA_DEPS)
MODULE_LINK_DEPS ?= $(MODULE_EXTRA_DEPS)

override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override OBJ := $(addprefix $(MODULE_OBJ_DIR)/,$(CFILES:.c=.c.o) $(ASFILES:.S=.S.o))
MODULE_INCLUDE_FLAGS := $(addprefix -I,$(MODULE_INCLUDE_DIRS)) -I$(MODULE_DIR)/

all: $(MODULE_OUTPUT)

ifeq ($(MODULE_KIND),staticlib)
$(MODULE_OUTPUT): $(OBJ) $(MODULE_LINK_DEPS) GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(MODULE_AR) rcs $@ $(OBJ)
else ifeq ($(MODULE_KIND),relocatable)
$(MODULE_OUTPUT): $(OBJ) $(MODULE_LINK_DEPS) GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(LD) -r $(OBJ) -o $@
else
$(MODULE_OUTPUT): $(OBJ) $(MODULE_LINK_DEPS) GNUmakefile
	mkdir -p "$$(dirname $@)"
	$(MODULE_LINKER) $(LDFLAGS) -shared $(OBJ) $(MODULE_LINK_LIBS) -o $@
endif

$(MODULE_OBJ_DIR)/%.c.o: %.c GNUmakefile $(MODULE_OBJ_DEPS)
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) $(MODULE_INCLUDE_FLAGS) -c $< -o $@

$(MODULE_OBJ_DIR)/%.S.o: %.S GNUmakefile $(MODULE_OBJ_DEPS)
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) $(MODULE_INCLUDE_FLAGS) -DASM_FILE -c $< -o $@

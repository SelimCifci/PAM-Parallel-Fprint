# Variables
TARGET_NAME = pam_parallel_fprint.so
BUILD_DIR = build
TARGET = $(BUILD_DIR)/$(TARGET_NAME)

SRC = src/main.c
OBJ = $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRC))

# Installation
PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib
INSTALL_DIR = $(DESTDIR)$(LIBDIR)/security

# Dependency discovery via pkg-config
PKG_DEPS = pam libsystemd
CFLAGS += -O2 -fPIC $(shell pkg-config --cflags $(PKG_DEPS))
LIBS += $(shell pkg-config --libs $(PKG_DEPS)) -pthread

# Default rule
all: $(TARGET)

# Link the shared library
$(TARGET): $(OBJ)
	@mkdir -p $(@D)
	$(CC) -shared -o $@ $^ $(LIBS)

# Compile source files into the build directory
$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Install rule
install: $(TARGET)
	sudo install -d $(INSTALL_DIR)
	sudo install -m 755 $(TARGET) $(INSTALL_DIR)/$(TARGET_NAME)

# Clean rule
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all install clean
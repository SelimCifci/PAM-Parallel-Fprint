.PHONY: all build install uninstall status test

all: build

build:
	cargo build --release

install:
	cargo install-pam

uninstall:
	cargo uninstall-pam

status:
	cargo status-pam

test:
	cargo test


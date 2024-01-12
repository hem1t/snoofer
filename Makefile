build=cargo build

run: build
	sudo ./target/debug/snooffer

run-release: build-release
	sudo ./target/release/snooffer

build:
	cargo build

build-release:
	cargo build --release

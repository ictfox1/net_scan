# MicroOS Makefile

NASM    := nasm
CC      := clang
LD      := ld
QEMU    := qemu-system-i386

SRC     := src
BUILD   := build

BOOT_BIN := $(BUILD)/boot.bin
KERNEL_BIN := $(BUILD)/kernel.bin
DISK_IMG := $(BUILD)/disk.img

KERNEL_SECTORS := 36

.PHONY: all clean run run-debug size

all: $(DISK_IMG)

$(BUILD):
	mkdir -p $(BUILD)

$(BOOT_BIN): $(SRC)/boot.asm | $(BUILD)
	$(NASM) -f bin $< -o $@

$(BUILD)/kernel.o: $(SRC)/kernel.c | $(BUILD)
	$(CC) -m16 -ffreestanding -fno-pie -nostdlib -c $< -o $@

$(KERNEL_BIN): $(BUILD)/kernel.o
	$(LD) -m elf_i386 -Ttext 0x1000 --oformat binary $< -o $@

$(DISK_IMG): $(BOOT_BIN) $(KERNEL_BIN)
	dd if=/dev/zero of=$@ bs=512 count=2880 status=none
	dd if=$(BOOT_BIN) of=$@ conv=notrunc status=none
	dd if=$(KERNEL_BIN) of=$@ bs=512 seek=1 conv=notrunc status=none
	@echo "Image ready: $@"

size: $(BOOT_BIN) $(KERNEL_BIN)
	@echo "Bootloader: $$(stat -c%s $(BOOT_BIN)) bytes (max 512)"
	@echo "Kernel:     $$(stat -c%s $(KERNEL_BIN)) bytes"
	@echo "Max kernel: $$(( $(KERNEL_SECTORS) * 512 )) bytes"

run: $(DISK_IMG)
	$(QEMU) -fda $(DISK_IMG) -boot a

run-debug: $(DISK_IMG)
	$(QEMU) -fda $(DISK_IMG) -boot a -d int -no-reboot -no-shutdown

clean:
	rm -rf $(BUILD)
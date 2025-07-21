ifeq ($(ARCH), x86_64)
	CROSS_COMPILE=x86_64-linux-musl-
else ifeq ($(ARCH), riscv64)
	CROSS_COMPILE=riscv64-linux-musl-
else ifeq ($(ARCH), loongarch64)
	CROSS_COMPILE=loongarch64-unknown-linux-gnu-
endif

CC=$(CROSS_COMPILE)gcc

.PHONY: all
all: main.c
	$(CC) -static -o nslookup main.c

.PHONY: install clean
install: all
	mv nslookup $(DADK_CURRENT_BUILD_DIR)/nslookup

clean:
	rm nslookup *.o


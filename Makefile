obj-m += cdra_core.o

ccflags-y := -std=gnu99

KVERSION ?= $(shell uname -r)
KERNEL_SOURCE ?= /lib/modules/$(KVERSION)/build

all:
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) modules
	echo /usr/local/bin/dtc -@ -I dts -O dtb rcio-overlay.dts -o rcio-overlay.dtb
	echo cp rcio-overlay.dtb /boot/overlays

install:
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) clean
	$(RM) rcio-overlay.dtb

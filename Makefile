MODULE_NAME = x86-executor

BUILD_DIR = /lib/modules/$(shell uname -r)/build
HEADERS_EXIST = $(shell if [ -d "${BUILD_DIR}" ]; then echo "${BUILD_DIR}"; \
                  else echo ""; fi)

ifneq (${HEADERS_EXIST}, ${BUILD_DIR})
  $(warning "Check you have linux headers installed")
  $(error   "${BUILD_DIR} does not exist!")
endif

SRC := main.c measurement.c templates.c

$(MODULE_NAME)-objs += $(SRC:.c=.o)

obj-m += $(MODULE_NAME).o

CFLAGS_measurement.o := -DDEBUG -Wno-unused-result -Wno-unused-label

ccflags-y+=-std=gnu99 -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules


clean:
	rm -f *.o *.ur-safe
	rm -rf *.o *.ko *.mod.c .tmp_versions modules.order Module.symvers


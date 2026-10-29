# relapse-offset-dumper
#
# Build against ps5-payload-dev/sdk (the newer SDK).
#
#   export PS5_PAYLOAD_SDK=/path/to/ps5-payload-dev-sdk
#   make
#
# Produces relapse-dumper.elf, loadable with elfldr on port 9021.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    # New SDK: toolchain/prospero.mk
    ifneq ($(wildcard $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk),)
        include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
    # Old SDK installed layout: make/toolchain.mk
    else ifneq ($(wildcard $(PS5_PAYLOAD_SDK)/make/toolchain.mk),)
        include $(PS5_PAYLOAD_SDK)/make/toolchain.mk
    # Old SDK source tree: toolchain.mk
    else ifneq ($(wildcard $(PS5_PAYLOAD_SDK)/toolchain.mk),)
        include $(PS5_PAYLOAD_SDK)/toolchain.mk
    else
        $(error Cannot find toolchain in $(PS5_PAYLOAD_SDK))
    endif
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := relapse-dumper.elf

CFLAGS := -Wall -Werror -g

all: $(ELF)

$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF) *.o

deploy: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

# ----------------------------------------------------------------------------
#  AUTOSAR HSM + Secure Boot reference project - host build
# ----------------------------------------------------------------------------
CC      ?= gcc
AR      ?= ar
CSTD    ?= -std=c99
WARN    := -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
           -Wno-unused-parameter
OPT     ?= -O2 -g
SAN     ?=
CFLAGS  += $(CSTD) $(WARN) $(OPT) $(SAN)
LDFLAGS += $(SAN)

BUILD   := build

INC_DIRS := common hsm/crypto hsm/core hsm/keystore hsm/she \
            autosar/Det autosar/Crypto autosar/CryIf autosar/Csm autosar/SecOC \
            config boot/platform boot/bootmanager boot/bootloader app tools tests
INCLUDES := $(addprefix -I,$(INC_DIRS))

HSM_SRCS := $(wildcard hsm/crypto/*.c hsm/core/*.c hsm/keystore/*.c hsm/she/*.c)
BSW_SRCS := $(wildcard autosar/*/*.c) $(wildcard config/*.c)
ECU_SRCS := $(wildcard boot/platform/*.c boot/bootmanager/*.c boot/bootloader/*.c app/*.c)
TOOL_LIB_SRCS := tools/Backend.c tools/Eol.c tools/Tester.c

LIB_SRCS := $(HSM_SRCS) $(BSW_SRCS) $(ECU_SRCS) $(TOOL_LIB_SRCS)
LIB_OBJS := $(patsubst %.c,$(BUILD)/obj/%.o,$(LIB_SRCS))
LIB      := $(BUILD)/libhsmecu.a

TEST_NAMES := test_crypto_primitives test_hsm_she test_csm_crypto_stack \
              test_secoc test_secure_boot_chain
TEST_BINS  := $(addprefix $(BUILD)/tests/,$(TEST_NAMES))

.PHONY: all lib tests test demo tools clean asan coverage

all: lib tests $(BUILD)/ecu_sim $(BUILD)/hsmtool

lib: $(LIB)

$(BUILD)/obj/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "  CC  $<"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(BUILD)/tests/%: tests/%.c tests/unity_lite.c $(LIB)
	@mkdir -p $(dir $@)
	@echo "  LD  $@"
	@$(CC) $(CFLAGS) $(INCLUDES) $< tests/unity_lite.c $(LIB) $(LDFLAGS) -o $@

tests: $(TEST_BINS)

test: tests
	@fail=0; for t in $(TEST_BINS); do echo; ./$$t || fail=1; done; echo; \
	if [ $$fail -eq 0 ]; then echo "ALL TEST SUITES PASSED"; else echo "TEST FAILURES"; exit 1; fi

$(BUILD)/ecu_sim: sim/ecu_sim_main.c $(LIB)
	@echo "  LD  $@"
	@$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB) $(LDFLAGS) -o $@

$(BUILD)/hsmtool: tools/hsmtool.c $(LIB)
	@echo "  LD  $@"
	@$(CC) $(CFLAGS) $(INCLUDES) $< $(LIB) $(LDFLAGS) -o $@

demo: $(BUILD)/ecu_sim
	./$(BUILD)/ecu_sim

tools: $(BUILD)/hsmtool

asan:
	$(MAKE) BUILD=build-asan SAN="-fsanitize=address,undefined -fno-omit-frame-pointer" OPT="-O1 -g" test

coverage:
	$(MAKE) BUILD=build-cov SAN="--coverage" OPT="-O0 -g" test

clean:
	rm -rf build build-asan build-cov

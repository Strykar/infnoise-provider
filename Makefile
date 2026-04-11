CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -I/usr/include/libftdi1 \
         -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
         -fcf-protection -fstack-clash-protection -fno-plt
LDFLAGS = -shared -lcrypto -linfnoise \
          -Wl,-z,relro,-z,now -Wl,-z,noexecstack
RM = rm -f

SRCDIR = src
TESTDIR = test
CONFDIR = conf

TARGET_LIB = infnoise.so
TEST_BIN = test_infnoise_prov
SRCS = $(SRCDIR)/infnoise_prov.c
OBJS = $(SRCDIR)/infnoise_prov.o

# Discover the OpenSSL provider module directory.
MODULESDIR := $(shell openssl version -m 2>/dev/null | sed 's/.*"\(.*\)"/\1/')
ifeq ($(MODULESDIR),)
    MODULESDIR = /usr/lib/ossl-modules
endif

.PHONY: all clean install test test-asan test-ubsan test-valgrind lint

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	strip --strip-unneeded $@

$(TEST_BIN): $(TESTDIR)/test_infnoise_prov.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto -linfnoise -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET_LIB)
	install -D -m 755 $(TARGET_LIB) $(DESTDIR)$(MODULESDIR)/$(TARGET_LIB)

test: $(TARGET_LIB) $(TEST_BIN)
	OPENSSL_MODULES=$(MODULESDIR) ./$(TEST_BIN)

# AddressSanitizer: detects buffer overflows, use-after-free, leaks.
test-asan: $(TESTDIR)/test_infnoise_prov.c $(SRCS)
	$(CC) -fPIC -Wall -Wextra -g -O1 -I/usr/include/libftdi1 \
	    -fsanitize=address -fno-omit-frame-pointer \
	    -o $(TEST_BIN)-asan $(TESTDIR)/test_infnoise_prov.c -lcrypto -linfnoise -lm
	$(CC) -fPIC -Wall -Wextra -g -O1 -I/usr/include/libftdi1 \
	    -fsanitize=address -fno-omit-frame-pointer -shared \
	    -o $(TARGET_LIB) $(SRCS) -lcrypto -linfnoise
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
	    OPENSSL_MODULES=$(MODULESDIR) ./$(TEST_BIN)-asan

# UndefinedBehaviorSanitizer: detects signed overflow, null deref, etc.
test-ubsan: $(TESTDIR)/test_infnoise_prov.c $(SRCS)
	$(CC) -fPIC -Wall -Wextra -g -O1 -I/usr/include/libftdi1 \
	    -fsanitize=undefined -fno-omit-frame-pointer \
	    -o $(TEST_BIN)-ubsan $(TESTDIR)/test_infnoise_prov.c -lcrypto -linfnoise -lm
	$(CC) -fPIC -Wall -Wextra -g -O1 -I/usr/include/libftdi1 \
	    -fsanitize=undefined -fno-omit-frame-pointer -shared \
	    -o $(TARGET_LIB) $(SRCS) -lcrypto -linfnoise
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	    OPENSSL_MODULES=$(MODULESDIR) ./$(TEST_BIN)-ubsan

# Valgrind: detects uninitialised reads, invalid accesses, leaks.
# Arch Linux note: valgrind requires glibc debug symbols.  Either:
#   1. Enable debuginfod: export DEBUGINFOD_URLS="https://debuginfod.archlinux.org"
#      and install the debuginfod package, or
#   2. Install a glibc-debug package if available.
test-valgrind: $(TARGET_LIB) $(TEST_BIN)
	@command -v valgrind >/dev/null 2>&1 || { echo "ERROR: valgrind not found"; exit 1; }
	OPENSSL_MODULES=$(MODULESDIR) valgrind \
	    --leak-check=full --show-leak-kinds=definite,possible \
	    --errors-for-leak-kinds=definite \
	    --track-origins=yes --error-exitcode=1 \
	    --suppressions=$(CONFDIR)/openssl.supp \
	    ./$(TEST_BIN)

# Static analysis with cppcheck and gcc -fanalyzer.
lint: $(SRCS) $(TESTDIR)/test_infnoise_prov.c
	@echo "--- cppcheck ---"
	cppcheck --enable=all --suppress=missingIncludeSystem \
	    --suppress=unusedFunction --std=c11 \
	    -I/usr/include/libftdi1 -I/usr/include \
	    $(SRCS) $(TESTDIR)/test_infnoise_prov.c 2>&1 || true
	@echo "--- gcc -fanalyzer ---"
	$(CC) -fPIC -Wall -Wextra -O2 -I/usr/include/libftdi1 \
	    -fanalyzer -fsyntax-only $(SRCS) 2>&1 || true
	$(CC) -Wall -Wextra -O2 -I/usr/include/libftdi1 \
	    -fanalyzer -fsyntax-only $(TESTDIR)/test_infnoise_prov.c 2>&1 || true

clean:
	-$(RM) $(TARGET_LIB) $(TEST_BIN) $(TEST_BIN)-asan $(TEST_BIN)-ubsan $(OBJS)

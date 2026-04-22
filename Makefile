CC = gcc
RM = rm -f

SRCDIR = src
TESTDIR = test
CONFDIR = conf
DOCDIR  = doc

MANDIR   ?= /usr/share/man
MAN7_SRC  = $(DOCDIR)/OSSL_PROVIDER-infnoise.7.md
MAN7_OUT  = $(DOCDIR)/OSSL_PROVIDER-infnoise.7

TARGET_LIB = infnoise.so
TEST_BIN = test_infnoise_prov
SRCS = $(SRCDIR)/infnoise_prov.c
OBJS = $(SRCDIR)/infnoise_prov.o

# Fail fast if pkg-config cannot find our required libraries.
# libinfnoise does not ship a .pc file upstream, so it stays explicit.
PKG_REQUIRES := libcrypto libftdi1
PKG_CHECK := $(shell pkg-config --exists $(PKG_REQUIRES) && echo ok)
ifneq ($(PKG_CHECK),ok)
    $(error pkg-config cannot find one of: $(PKG_REQUIRES).  Install \
        the corresponding -dev / -devel packages)
endif

PKG_CFLAGS := $(shell pkg-config --cflags $(PKG_REQUIRES))
PKG_LIBS   := $(shell pkg-config --libs   $(PKG_REQUIRES))
INFNOISE_LIB := -linfnoise

CFLAGS = -fPIC -Wall -Wextra -O2 $(PKG_CFLAGS) \
         -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
         -fcf-protection -fstack-clash-protection -fno-plt
LDFLAGS = -shared $(PKG_LIBS) $(INFNOISE_LIB) \
          -Wl,-z,relro,-z,now -Wl,-z,noexecstack

# Discover the OpenSSL provider module directory.
MODULESDIR := $(shell openssl version -m 2>/dev/null | sed 's/.*"\(.*\)"/\1/')
ifeq ($(MODULESDIR),)
    MODULESDIR = /usr/lib/ossl-modules
endif

.PHONY: all clean install install-man man test test-asan test-ubsan test-valgrind test-soak test-soak-short plot-soak lint

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	strip --strip-unneeded $@

$(TEST_BIN): $(TESTDIR)/test_infnoise_prov.c
	$(CC) $(CFLAGS) -o $@ $< $(PKG_LIBS) $(INFNOISE_LIB) -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET_LIB)
	install -D -m 755 $(TARGET_LIB) $(DESTDIR)$(MODULESDIR)/$(TARGET_LIB)

# Manpage build (pandoc) and install.  Kept separate from the default
# build so pandoc is only a dependency for packagers who ship the page.
man: $(MAN7_OUT)

$(MAN7_OUT): $(MAN7_SRC)
	@command -v pandoc >/dev/null 2>&1 || { \
	    echo "ERROR: pandoc is required to build the manpage"; exit 1; }
	pandoc -s -t man -o $@ $<

install-man: $(MAN7_OUT)
	install -D -m 644 $(MAN7_OUT) \
	    $(DESTDIR)$(MANDIR)/man7/OSSL_PROVIDER-infnoise.7

test: $(TARGET_LIB) $(TEST_BIN)
	OPENSSL_MODULES=$(MODULESDIR) ./$(TEST_BIN)

# Shared flags for sanitizer builds.
SAN_CFLAGS = -fPIC -Wall -Wextra -g -O1 $(PKG_CFLAGS) -fno-omit-frame-pointer
SAN_LIBS   = $(PKG_LIBS) $(INFNOISE_LIB)

# AddressSanitizer: detects buffer overflows, use-after-free, leaks.
test-asan: $(TESTDIR)/test_infnoise_prov.c $(SRCS)
	$(CC) $(SAN_CFLAGS) -fsanitize=address \
	    -o $(TEST_BIN)-asan $(TESTDIR)/test_infnoise_prov.c $(SAN_LIBS) -lm
	$(CC) $(SAN_CFLAGS) -fsanitize=address -shared \
	    -o $(TARGET_LIB) $(SRCS) $(SAN_LIBS)
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
	    OPENSSL_MODULES=$(MODULESDIR) ./$(TEST_BIN)-asan

# UndefinedBehaviorSanitizer: detects signed overflow, null deref, etc.
test-ubsan: $(TESTDIR)/test_infnoise_prov.c $(SRCS)
	$(CC) $(SAN_CFLAGS) -fsanitize=undefined \
	    -o $(TEST_BIN)-ubsan $(TESTDIR)/test_infnoise_prov.c $(SAN_LIBS) -lm
	$(CC) $(SAN_CFLAGS) -fsanitize=undefined -shared \
	    -o $(TARGET_LIB) $(SRCS) $(SAN_LIBS)
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	    OPENSSL_MODULES=$(MODULESDIR) ./$(TEST_BIN)-ubsan

# Valgrind: detects uninitialised reads, invalid accesses, leaks.
# Linux note: valgrind requires glibc debug symbols.  Either:
#   1. On Arch Linux, enable debuginfod: export DEBUGINFOD_URLS="https://debuginfod.archlinux.org"
#      and install the debuginfod package, or
#   2. Other distros, install the glibc-debug package.
test-valgrind: $(TARGET_LIB) $(TEST_BIN)
	@command -v valgrind >/dev/null 2>&1 || { echo "ERROR: valgrind not found"; exit 1; }
	OPENSSL_MODULES=$(MODULESDIR) valgrind \
	    --leak-check=full --show-leak-kinds=definite,possible \
	    --errors-for-leak-kinds=definite \
	    --track-origins=yes --error-exitcode=1 \
	    --suppressions=$(CONFDIR)/openssl.supp \
	    ./$(TEST_BIN)

# Capture a raw (un-whitened) sample from the TRNG for visual comparison.
# The scatter plot of raw output shows the INM's preferred bit states;
# whitened output should fill the plane uniformly.
RAW_SAMPLE_BYTES ?= 65536
SOAK_PLOT = $(TESTDIR)/plot_samples.py

# Long-duration soak: drives our provider directly via EVP_RAND for
# SOAK_SECONDS (default 24 h).  Exercises dispatch, spill buffer, three-
# phase generate, lifecycle churn, and RSS for slow leaks.  Dumps samples
# every 5 min for offline ent/rngtest/dieharder analysis.
# Captures raw TRNG output and generates scatter/heatmap plots at the end.
test-soak: $(TARGET_LIB) $(TESTDIR)/test_infnoise_soak.c
	$(CC) $(CFLAGS) -o test_infnoise_soak $(TESTDIR)/test_infnoise_soak.c $(PKG_LIBS)
	@SOAK_DIR=$${SOAK_SAMPLE_DIR:-/tmp/infnoise-soak-$$$$}; \
	 mkdir -p "$$SOAK_DIR"; \
	 if command -v infnoise >/dev/null 2>&1; then \
	     echo "capturing $(RAW_SAMPLE_BYTES) bytes of raw TRNG output..."; \
	     infnoise --raw 2>/dev/null | head -c $(RAW_SAMPLE_BYTES) > "$$SOAK_DIR/raw.bin"; \
	     echo "raw sample: $$SOAK_DIR/raw.bin"; \
	 else \
	     echo "warn: infnoise CLI not found, skipping raw capture"; \
	 fi; \
	 OPENSSL_MODULES=$(MODULESDIR) \
	     OPENSSL_CONF=$(CONFDIR)/infnoise-provider.cnf \
	     SOAK_SAMPLE_DIR="$$SOAK_DIR" \
	     ./test_infnoise_soak; RC=$$?; \
	 $(MAKE) --no-print-directory plot-soak SOAK_SAMPLE_DIR="$$SOAK_DIR"; \
	 exit $$RC

# 1-hour variant.  Override duration inline: `make test-soak-short SOAK_SECONDS=7200`
test-soak-short: $(TARGET_LIB) $(TESTDIR)/test_infnoise_soak.c
	$(CC) $(CFLAGS) -o test_infnoise_soak $(TESTDIR)/test_infnoise_soak.c $(PKG_LIBS)
	@SOAK_DIR=$${SOAK_SAMPLE_DIR:-/tmp/infnoise-soak-$$$$}; \
	 mkdir -p "$$SOAK_DIR"; \
	 if command -v infnoise >/dev/null 2>&1; then \
	     echo "capturing $(RAW_SAMPLE_BYTES) bytes of raw TRNG output..."; \
	     infnoise --raw 2>/dev/null | head -c $(RAW_SAMPLE_BYTES) > "$$SOAK_DIR/raw.bin"; \
	     echo "raw sample: $$SOAK_DIR/raw.bin"; \
	 else \
	     echo "warn: infnoise CLI not found, skipping raw capture"; \
	 fi; \
	 OPENSSL_MODULES=$(MODULESDIR) \
	     OPENSSL_CONF=$(CONFDIR)/infnoise-provider.cnf \
	     SOAK_SAMPLE_DIR="$$SOAK_DIR" \
	     SOAK_SECONDS=$${SOAK_SECONDS:-3600} \
	     ./test_infnoise_soak; RC=$$?; \
	 $(MAKE) --no-print-directory plot-soak SOAK_SAMPLE_DIR="$$SOAK_DIR"; \
	 exit $$RC

# Generate scatter and heatmap plots from soak sample files.
# Uses SOAK_SAMPLE_DIR if set, otherwise finds the most recent soak directory.
plot-soak:
	@SOAK_DIR="$${SOAK_SAMPLE_DIR}"; \
	 if [ -z "$$SOAK_DIR" ]; then \
	     SOAK_DIR=$$(ls -td /tmp/infnoise-soak-* 2>/dev/null | head -1); \
	 fi; \
	 if [ -z "$$SOAK_DIR" ]; then echo "no soak directory found"; exit 1; fi; \
	 echo "plotting from $$SOAK_DIR"; \
	 RAW="$$SOAK_DIR/raw.bin"; \
	 WHITE=$$(ls -t "$$SOAK_DIR"/sample-*.bin 2>/dev/null | head -1); \
	 if [ -f "$$RAW" ] && [ -n "$$WHITE" ]; then \
	     python3 $(SOAK_PLOT) "$$RAW" "$$WHITE" --no-show; \
	 elif [ -f "$$RAW" ]; then \
	     python3 $(SOAK_PLOT) "$$RAW" --no-show; \
	 elif [ -n "$$WHITE" ]; then \
	     python3 $(SOAK_PLOT) "$$WHITE" --no-show; \
	 else \
	     echo "no sample files found in $$SOAK_DIR"; exit 1; \
	 fi

# Static analysis with cppcheck and gcc -fanalyzer.
lint: $(SRCS) $(TESTDIR)/test_infnoise_prov.c
	@echo "--- cppcheck ---"
	cppcheck --enable=all --suppress=missingIncludeSystem \
	    --suppress=unusedFunction --std=c11 \
	    $(PKG_CFLAGS) \
	    $(SRCS) $(TESTDIR)/test_infnoise_prov.c 2>&1 || true
	@echo "--- gcc -fanalyzer ---"
	$(CC) -fPIC -Wall -Wextra -O2 $(PKG_CFLAGS) \
	    -fanalyzer -fsyntax-only $(SRCS) 2>&1 || true
	$(CC) -Wall -Wextra -O2 $(PKG_CFLAGS) \
	    -fanalyzer -fsyntax-only $(TESTDIR)/test_infnoise_prov.c 2>&1 || true

clean:
	-$(RM) $(TARGET_LIB) $(TEST_BIN) $(TEST_BIN)-asan $(TEST_BIN)-ubsan test_infnoise_soak
	-$(RM) *-plots.png *-scatter.png *-heatmap.png
	-$(RM) $(SRCDIR)/*.o $(TESTDIR)/*.o
	-$(RM) core core.*
	-$(RM) $(MAN7_OUT)

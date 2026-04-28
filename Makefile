CC = gcc
RM = rm -f

SRCDIR  = src
TESTDIR = tests
CONFDIR = conf
DOCDIR  = docs
FUZZ_DIR = fuzz

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

.PHONY: all clean install install-man man test test-asan test-ubsan test-tsan test-alloc test-valgrind test-soak test-soak-short plot-soak lint fuzz fuzz-clean sbom mutation mutation-clean

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

# ThreadSanitizer: detects data races on the provider's per-context state
# under concurrent EVP_RAND_CTX use.  Uses the fuzz mock libinfnoise so no
# USB device is needed.  TSan and libFuzzer don't compose, so this is its
# own binary built independently of the fuzz suite.
TSAN_CFLAGS = -g -O1 -Wall -Wextra $(PKG_CFLAGS) -fno-omit-frame-pointer \
              -fsanitize=thread -pthread
TSAN_LIBS   = $(shell pkg-config --libs libcrypto) -pthread
test-tsan: $(TESTDIR)/test_infnoise_tsan.c $(FUZZ_DIR)/mock_libinfnoise.c \
           $(SRCS)
	$(CC) $(TSAN_CFLAGS) -c $(FUZZ_DIR)/mock_libinfnoise.c \
	    -o $(FUZZ_DIR)/mock_libinfnoise.tsan.o
	$(CC) $(TSAN_CFLAGS) -o test_infnoise_tsan \
	    $(TESTDIR)/test_infnoise_tsan.c \
	    $(FUZZ_DIR)/mock_libinfnoise.tsan.o $(TSAN_LIBS)
	TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 \
	    ./test_infnoise_tsan

# Allocator-failure injection.  Installs CRYPTO_set_mem_functions wrapper
# that fails on a chosen iteration count, drives each provider alloc site,
# and verifies the documented failure indicator + clean state.  Catches
# regressions in the alloc-path NULL checks (Tier A audit verifies these
# today; this test guards against future drift).
ALLOC_CFLAGS = -g -O1 -Wall -Wextra $(PKG_CFLAGS) -fno-omit-frame-pointer \
               -fsanitize=address,undefined
ALLOC_LIBS   = $(shell pkg-config --libs libcrypto)
test-alloc: $(TESTDIR)/test_infnoise_alloc.c $(FUZZ_DIR)/mock_libinfnoise.c \
            $(SRCS)
	$(CC) $(ALLOC_CFLAGS) -c $(FUZZ_DIR)/mock_libinfnoise.c \
	    -o $(FUZZ_DIR)/mock_libinfnoise.alloc.o
	$(CC) $(ALLOC_CFLAGS) -o test_infnoise_alloc \
	    $(TESTDIR)/test_infnoise_alloc.c \
	    $(FUZZ_DIR)/mock_libinfnoise.alloc.o $(ALLOC_LIBS)
	./test_infnoise_alloc

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
	-$(RM) sbom.spdx.txt

# Generate an SPDX-tag-value SBOM for the runtime dependencies of
# infnoise.so.  No external tools required — uses pkg-config and ldconfig.
# Output: sbom.spdx.txt, attached to GitHub release pages alongside the
# .so and signature.
sbom: $(TARGET_LIB)
	@echo "SPDXVersion: SPDX-2.3"               > sbom.spdx.txt
	@echo "DataLicense: CC0-1.0"                >> sbom.spdx.txt
	@echo "SPDXID: SPDXRef-DOCUMENT"            >> sbom.spdx.txt
	@echo "DocumentName: infnoise-provider"     >> sbom.spdx.txt
	@echo "DocumentNamespace: https://github.com/Strykar/infnoise-provider/sbom/$$(date -u +%Y%m%dT%H%M%SZ)" >> sbom.spdx.txt
	@echo "Creator: Tool: infnoise-provider-Makefile" >> sbom.spdx.txt
	@echo "Created: $$(date -u +%Y-%m-%dT%H:%M:%SZ)"  >> sbom.spdx.txt
	@echo ""                                    >> sbom.spdx.txt
	@echo "##### Package: infnoise-provider"    >> sbom.spdx.txt
	@echo "PackageName: infnoise-provider"      >> sbom.spdx.txt
	@echo "SPDXID: SPDXRef-Package-infnoise-provider" >> sbom.spdx.txt
	@echo "PackageVersion: $$(git describe --tags --always 2>/dev/null || echo 'unversioned')" >> sbom.spdx.txt
	@echo "PackageDownloadLocation: https://github.com/Strykar/infnoise-provider" >> sbom.spdx.txt
	@echo "PackageLicenseDeclared: GPL-2.0-or-later" >> sbom.spdx.txt
	@echo "PackageLicenseConcluded: GPL-2.0-or-later" >> sbom.spdx.txt
	@echo "PackageFileName: infnoise.so"        >> sbom.spdx.txt
	@echo "PackageChecksum: SHA256: $$(sha256sum $(TARGET_LIB) | cut -d' ' -f1)" >> sbom.spdx.txt
	@echo ""                                    >> sbom.spdx.txt
	@echo "##### Runtime dependencies (read via pkg-config / ldconfig)" >> sbom.spdx.txt
	@for lib in libcrypto libftdi1 libusb-1.0; do \
	    ver=$$(pkg-config --modversion $$lib 2>/dev/null || echo 'unknown'); \
	    case "$$lib" in \
	      libcrypto) lic="Apache-2.0" ;; \
	      libftdi1)  lic="LGPL-2.1-only" ;; \
	      libusb-1.0) lic="LGPL-2.1-or-later" ;; \
	    esac; \
	    echo ""                                 >> sbom.spdx.txt; \
	    echo "PackageName: $$lib"               >> sbom.spdx.txt; \
	    spdxid=$$(echo $$lib | tr -c 'A-Za-z0-9' '-' | sed 's/-*$$//'); \
	    echo "SPDXID: SPDXRef-Package-$$spdxid" >> sbom.spdx.txt; \
	    echo "PackageVersion: $$ver"            >> sbom.spdx.txt; \
	    echo "PackageDownloadLocation: NOASSERTION" >> sbom.spdx.txt; \
	    echo "PackageLicenseDeclared: $$lic"    >> sbom.spdx.txt; \
	    echo "PackageLicenseConcluded: $$lic"   >> sbom.spdx.txt; \
	    echo "FilesAnalyzed: false"             >> sbom.spdx.txt; \
	done
	@echo ""                                    >> sbom.spdx.txt
	@echo "PackageName: libinfnoise"            >> sbom.spdx.txt
	@echo "SPDXID: SPDXRef-Package-libinfnoise" >> sbom.spdx.txt
	@echo "PackageVersion: Strykar/infnoise@libinfnoise-error-codes" >> sbom.spdx.txt
	@echo "PackageDownloadLocation: https://github.com/Strykar/infnoise-provider/blob/master/docs/ARCHITECTURE.txt#section-6" >> sbom.spdx.txt
	@echo "PackageLicenseDeclared: GPL-3.0-or-later" >> sbom.spdx.txt
	@echo "PackageLicenseConcluded: GPL-3.0-or-later" >> sbom.spdx.txt
	@echo "FilesAnalyzed: false"                >> sbom.spdx.txt
	@echo ""                                    >> sbom.spdx.txt
	@echo "##### Relationships"                 >> sbom.spdx.txt
	@for spdx in libcrypto libftdi1 libusb-1-0 libinfnoise; do \
	    echo "Relationship: SPDXRef-Package-infnoise-provider DEPENDS_ON SPDXRef-Package-$$spdx" >> sbom.spdx.txt; \
	done
	@echo ""
	@echo "wrote sbom.spdx.txt ($$(wc -l < sbom.spdx.txt) lines)"

################################
# Fuzzing (requires clang + compiler-rt for -fsanitize=fuzzer)
################################

FUZZ_CC  ?= clang

# Compile-time flags: same headers as the main build, but no hardening that
# conflicts with sanitiser instrumentation (-fstack-protector-strong and
# -D_FORTIFY_SOURCE can suppress fuzzer-induced crashes that we want to see).
FUZZ_CFLAGS = -g -O1 -Wall -Wextra \
              $(shell pkg-config --cflags libcrypto libftdi1) \
              -fno-omit-frame-pointer \
              -fsanitize=fuzzer,address,undefined

# Link: libcrypto only.  The mock object provides the infnoise symbols;
# real libftdi1 and libinfnoise are intentionally excluded so no USB
# code runs during fuzzing.
FUZZ_LDFLAGS = $(shell pkg-config --libs libcrypto) \
               $(FUZZ_DIR)/mock_libinfnoise.o

FUZZ_TARGETS = $(FUZZ_DIR)/fuzz_params \
               $(FUZZ_DIR)/fuzz_dispatch \
               $(FUZZ_DIR)/fuzz_ossl_params \
               $(FUZZ_DIR)/fuzz_spill_oracle \
               $(FUZZ_DIR)/fuzz_provider_init

fuzz: $(FUZZ_TARGETS)

$(FUZZ_DIR)/mock_libinfnoise.o: $(FUZZ_DIR)/mock_libinfnoise.c \
                                 $(FUZZ_DIR)/mock_libinfnoise.h
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c $< -o $@

$(FUZZ_DIR)/fuzz_%: $(FUZZ_DIR)/fuzz_%.c $(FUZZ_DIR)/mock_libinfnoise.o
	$(FUZZ_CC) $(FUZZ_CFLAGS) $< $(FUZZ_LDFLAGS) -o $@

fuzz-clean:
	-$(RM) $(FUZZ_TARGETS) $(FUZZ_DIR)/mock_libinfnoise.o
	-$(RM) -r $(FUZZ_DIR)/corpus-*

################################
# Mutation testing (Mull, https://github.com/mull-project/mull)
#
# Release-prep tool, not part of the per-patch checklist.  Run before
# tagging a signed release to confirm the spill-buffer assertions
# remain load-bearing after any provider edits.
#
# Mull's IR frontend ships as a clang plugin built against a specific
# LLVM version.  On Arch the mull-bin package targets LLVM 20, so the
# build needs the matching clang-20 binary; system clang (often newer)
# will reject the plugin's API version.
#
#   pacman -S mull-bin clang20
#
# Override MULL_CLANG / MULL_PLUGIN if your distro installs them
# elsewhere.  The mutation pool is scoped to src/infnoise_prov.c via
# mull.yml so the score reflects provider assertions, not harness
# self-tests.
################################

MULL_DIR     = mutation
MULL_CLANG  ?= /usr/lib/llvm20/bin/clang-20
MULL_PLUGIN ?= /usr/lib/mull-ir-frontend-20
MULL_RUNNER ?= mull-runner-20

MULL_CFLAGS = -grecord-command-line -g -O0 -Wall -Wextra \
              $(shell pkg-config --cflags libcrypto libftdi1) \
              -fno-omit-frame-pointer
MULL_LIBS   = $(shell pkg-config --libs libcrypto) -lpthread

$(MULL_DIR)/mock_libinfnoise.o: $(FUZZ_DIR)/mock_libinfnoise.c \
                                $(FUZZ_DIR)/mock_libinfnoise.h
	$(MULL_CLANG) $(MULL_CFLAGS) -c $< -o $@

$(MULL_DIR)/replay.o: $(MULL_DIR)/replay.c
	$(MULL_CLANG) $(MULL_CFLAGS) -c $< -o $@

# Only this TU is compiled with the Mull plugin.  It textually #includes
# src/infnoise_prov.c so mutations target provider IR; mull.yml's
# includePaths regex drops mutations whose debug info points at the
# harness or oracle code.
$(MULL_DIR)/oracle_target.o: $(FUZZ_DIR)/fuzz_spill_oracle.c \
                             $(SRCDIR)/infnoise_prov.c
	$(MULL_CLANG) -fpass-plugin=$(MULL_PLUGIN) $(MULL_CFLAGS) \
	    -c $< -o $@

$(MULL_DIR)/runner: $(MULL_DIR)/oracle_target.o $(MULL_DIR)/replay.o \
                    $(MULL_DIR)/mock_libinfnoise.o
	$(MULL_CLANG) $^ $(MULL_LIBS) -o $@

mutation: $(MULL_DIR)/runner
	@command -v $(MULL_RUNNER) >/dev/null 2>&1 || { \
	    echo "ERROR: $(MULL_RUNNER) not found (install mull-bin)"; exit 1; }
	$(MULL_RUNNER) $(MULL_DIR)/runner

mutation-clean:
	-$(RM) $(MULL_DIR)/runner $(MULL_DIR)/*.o

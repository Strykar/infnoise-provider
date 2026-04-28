// Copyright (C) 2025-2026 Avinash H. Duduskar.
// SPDX-License-Identifier: GPL-2.0-or-later
// https://github.com/Strykar/infnoise-provider
//
// Mutation testing driver: replays the persistent oracle fuzz corpus.
//
// Mull mutates src/infnoise_prov.c (scoped via mull.yml).  For each
// mutation, this binary runs once; the corpus is fed through the same
// LLVMFuzzerTestOneInput entry point used by libFuzzer.  Any divergence
// between provider and oracle, canary breach, or cleanse violation
// already trips __builtin_trap inside the harness, which Mull records
// as a kill (SIGILL).  Surviving mutants imply assertions that did not
// catch the change - the load-bearing test of the test suite.

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define CORPUS_DIR "fuzz/corpus/fuzz_spill_oracle"

static void run_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return; }
    size_t sz = (size_t)st.st_size;
    void *m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return;
    (void)LLVMFuzzerTestOneInput((const uint8_t *)m, sz);
    munmap(m, sz);
}

int main(void)
{
    DIR *d = opendir(CORPUS_DIR);
    if (!d) {
        fprintf(stderr, "replay: cannot open %s (run from project root)\n",
                CORPUS_DIR);
        return 2;
    }
    char path[PATH_MAX];
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if ((size_t)snprintf(path, sizeof(path), "%s/%s",
                             CORPUS_DIR, e->d_name) >= sizeof(path))
            continue;
        run_file(path);
    }
    closedir(d);
    return 0;
}

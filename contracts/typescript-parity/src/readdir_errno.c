#include <dirent.h>
#include <errno.h>
#include <stddef.h>

/*
 * Capture readdir() and errno in one native call. JavaScript-side errno access
 * cannot make this atomic and may misclassify a partial enumeration as EOF.
 * The fault hook is process-local and exists only for deterministic regression
 * coverage of EIO after N valid entries.
 */
static int hermternal_fault_after = -1;
static int hermternal_entry_count = 0;

void hermternal_readdir_fault_after(int count) {
    hermternal_fault_after = count;
    hermternal_entry_count = 0;
}

int hermternal_readdir_entry_count(void) {
    return hermternal_entry_count;
}

void *hermternal_readdir_checked(void *directory, int *captured_errno) {
    if (hermternal_fault_after == 0) {
        hermternal_fault_after = -1;
        *captured_errno = EIO;
        return NULL;
    }

    errno = 0;
    struct dirent *entry = readdir((DIR *)directory);
    *captured_errno = errno;
    if (entry != NULL) {
        hermternal_entry_count += 1;
        if (hermternal_fault_after > 0) {
            hermternal_fault_after -= 1;
        }
    }
    return entry;
}

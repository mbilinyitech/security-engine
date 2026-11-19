/* IOMMU containment test: run inside the VM, against a real PCI device behind a real IOMMU.
 *
 * The claim under test is not "the module returned 0". It is that with the domain empty, the
 * device cannot reach memory, and after a grant it can reach exactly one buffer. We check the
 * translation tables the hardware uses, because that is what decides whether a DMA lands. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SYSFS "/sys/kernel/sov_iommu"

static int read_file(const char *path, char *buf, size_t len)
{
FILE *f = fopen(path, "r");
size_t n;

if (!f)
return -1;
n = fread(buf, 1, len - 1, f);
buf[n] = '\0';
fclose(f);
return 0;
}

static int write_file(const char *path, const char *val)
{
FILE *f = fopen(path, "w");

if (!f)
return -1;
if (fputs(val, f) < 0) {
fclose(f);
return -1;
}
return fclose(f) == 0 ? 0 : -1;
}

int main(void)
{
char state[1024];
int pass = 0, fail = 0;

#define CHECK(cond, msg) do { \
if (cond) { printf("  ok   %s\n", msg); pass++; } \
else { printf("  FAIL %s\n", msg); fail++; } \
} while (0)

if (read_file(SYSFS "/state", state, sizeof state)) {
printf("  FAIL cannot read %s/state\n", SYSFS);
printf("RESULT: iommu FAILED\n");
return 1;
}

printf("--- state after isolation ---\n%s", state);

/* 1. The domain exists and reports itself empty. */
CHECK(strstr(state, "domain=present") != NULL, "domain attached");
/* The load-bearing check. Reading our own pointer proves nothing; this is the IOMMU's
 * answer to "which domain is this device in". */
CHECK(strstr(state, "device_in_our_domain=1") != NULL,
      "the device is in our domain according to the IOMMU, not just our bookkeeping");
CHECK(strstr(state, "mapped=0") != NULL, "nothing mapped yet");
CHECK(strstr(state, "phys_at_0=0x0000000000000000") != NULL,
      "IOVA 0 does not translate (DMA to 0 faults)");
CHECK(strstr(state, "phys_at_iova=0x0000000000000000") != NULL,
      "the grant IOVA does not translate yet (DMA faults)");

/* 2. Map 4 KiB read-only. */
CHECK(write_file(SYSFS "/map", "4096 read") == 0, "map 4096 bytes read-only");
CHECK(read_file(SYSFS "/state", state, sizeof state) == 0, "state readable after map");
printf("--- state after grant ---\n%s", state);
CHECK(strstr(state, "mapped=1") != NULL, "buffer is mapped");
CHECK(strstr(state, "size=4096") != NULL, "size is 4096");
CHECK(strstr(state, "phys_at_iova=0x0000000000000000") == NULL,
      "the grant IOVA now translates to real memory");
CHECK(strstr(state, "phys_at_0=0x0000000000000000") != NULL,
      "IOVA 0 still does not translate (only the grant is reachable)");

/* 3. Revoke. */
CHECK(write_file(SYSFS "/unmap", "1") == 0, "unmap");
CHECK(read_file(SYSFS "/state", state, sizeof state) == 0, "state readable after unmap");
printf("--- state after revoke ---\n%s", state);
CHECK(strstr(state, "mapped=0") != NULL, "buffer is unmapped");
CHECK(strstr(state, "phys_at_iova=0x0000000000000000") != NULL,
      "the grant IOVA faults again after revoke");

/* 4. Second map after revoke must work: revocation is not a one-way door. */
CHECK(write_file(SYSFS "/map", "8192 rw") == 0, "re-map 8192 bytes read-write");
CHECK(read_file(SYSFS "/state", state, sizeof state) == 0, "state readable after re-map");
CHECK(strstr(state, "size=8192") != NULL, "size is 8192");
CHECK(write_file(SYSFS "/unmap", "1") == 0, "final unmap");

/* 5. Double map while mapped is refused. */
write_file(SYSFS "/map", "4096 read");
CHECK(write_file(SYSFS "/map", "4096 read") != 0, "second map while mapped is refused");
write_file(SYSFS "/unmap", "1");

printf("RESULT: %s (%d passed, %d failed)\n", fail ? "iommu FAILED" : "iommu passed",
       pass, fail);
return fail ? 1 : 0;
}

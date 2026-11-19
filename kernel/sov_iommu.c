// Sovereign IOMMU containment: real DMA isolation for a plug-in PCI device.
//
// The problem this solves
// -----------------------
// A character device that refuses a bad token does nothing about DMA. A PCI function with bus
// mastering enabled can write to any physical address the platform allows, whether or not any
// driver agreed to it. That is the rogue-card attack, and a token check cannot stop it.
//
// What this module actually does
// ------------------------------
//   1. Finds the target PCI function by BDF and refuses to proceed unless it has an IOMMU
//      group. A device the IOMMU cannot group is a device this cannot contain, and saying so is
//      better than claiming success.
//   2. Releases any driver bound to it, so nothing else programs the device while it is held.
//   3. Detaches it from the default domain, then attaches it to a freshly allocated domain with
//      no mappings. From that point every DMA the device issues fails translation: the IOMMU
//      has no IOVA -> PA entry, so the write never reaches RAM.
//   4. Maps a buffer only when asked, with an explicit size and direction, and unmaps on
//      revoke. Between map and unmap the device can reach exactly that buffer and nothing else.
//
// The containment is enforced by hardware, not by this module's bookkeeping. With the domain
// empty, a malicious device that ignores every protocol still cannot write to memory.
//
// What this does NOT do
// ---------------------
//   * It is not a bus-level filter. A driver that binds later would attach its own domain.
//     Detaching on load closes that window for as long as the module is loaded.
//   * It maps a kernel-allocated buffer, not user pages. Mapping user memory needs pinning and
//     a lifetime story this module does not have.
//   * No PASID, no nested translation, no ATS/PRI.

#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/io.h>

#define SOV_IOVA_BASE 0x100000ULL /* start mappings at 1 MiB so a mapping at 0 stands out */

struct sov_iommu {
	struct pci_dev *pdev;
	struct iommu_group *group;
	struct iommu_domain *domain;
	void *buffer;
	dma_addr_t iova;
	size_t size;
	bool mapped;
};

static struct sov_iommu sov;

/* Find a PCI function by BDF, e.g. "0000:00:04.0". Returns a referenced pci_dev or NULL. */
static struct pci_dev *sov_find_device(const char *bdf)
{
	unsigned int domain, bus, slot, func;

	if (!bdf)
		return NULL;
	if (sscanf(bdf, "%x:%x:%x.%x", &domain, &bus, &slot, &func) != 4)
		return NULL;

	return pci_get_domain_bus_and_slot(domain, bus, PCI_DEVFN(slot, func));
}

/* Put the device into an empty domain. After this returns, every DMA from it faults. */
static int sov_isolate(struct sov_iommu *s)
{
	int ret;

	s->group = iommu_group_get(&s->pdev->dev);
	if (!s->group) {
		pr_err("sov_iommu: %s has no IOMMU group; it cannot be contained\n",
		       pci_name(s->pdev));
		return -ENODEV;
	}

	/* Take the device away from its driver first. A bound driver keeps issuing DMA and would
	 * race the domain swap. */
	if (s->pdev->dev.driver) {
		device_release_driver(&s->pdev->dev);
		pr_info("sov_iommu: released driver from %s\n", pci_name(s->pdev));
	}

	/* Attach to a fresh, empty domain. iommu_attach_group replaces whatever domain the
	 * device was in (including the default one), so no explicit detach is needed. */
	s->domain = iommu_domain_alloc(&pci_bus_type);
	if (!s->domain) {
		pr_err("sov_iommu: domain allocation failed\n");
		ret = -ENOMEM;
		goto out_group;
	}

	ret = iommu_attach_group(s->domain, s->group);
	if (ret) {
		pr_err("sov_iommu: attach failed: %d\n", ret);
		goto out_domain;
	}

	/* Confirm the device really is in the domain we allocated. Reading our own pointer
	 * would prove nothing; this asks the IOMMU where the device actually is. */
	if (iommu_get_domain_for_dev(&s->pdev->dev) != s->domain) {
		pr_err("sov_iommu: device is not in the new domain after attach\n");
		iommu_detach_group(s->domain, s->group);
		ret = -EIO;
		goto out_domain;
	}

	/* And that the domain has no translations. A non-empty domain here would mean the
	 * device can still reach memory we did not grant. */
	if (iommu_iova_to_phys(s->domain, SOV_IOVA_BASE)) {
		pr_err("sov_iommu: domain is not empty after attach; refusing\n");
		iommu_detach_group(s->domain, s->group);
		ret = -EBUSY;
		goto out_domain;
	}

	pr_info("sov_iommu: %s contained in an empty domain\n", pci_name(s->pdev));
	return 0;

out_domain:
	iommu_domain_free(s->domain);
	s->domain = NULL;
out_group:
	iommu_group_put(s->group);
	s->group = NULL;
	return ret;
}

/* Map one buffer. Only meaningful once a grant has been accepted. */
static int sov_grant_dma(struct sov_iommu *s, size_t size, bool writable)
{
	size_t bytes;
	int prot = IOMMU_READ;
	int ret;

	if (!s->domain)
		return -EINVAL;
	if (s->mapped)
		return -EBUSY;
	if (size == 0)
		return -EINVAL;
	if (writable)
		prot |= IOMMU_WRITE;

	bytes = PAGE_ALIGN(size);

	s->buffer = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(bytes));
	if (!s->buffer)
		return -ENOMEM;

	s->iova = SOV_IOVA_BASE;
	ret = iommu_map(s->domain, s->iova, virt_to_phys(s->buffer), bytes, prot,
			GFP_KERNEL);
	if (ret) {
		pr_err("sov_iommu: iommu_map failed: %d\n", ret);
		free_pages((unsigned long)s->buffer, get_order(bytes));
		s->buffer = NULL;
		return ret;
	}

	s->size = size;
	s->mapped = true;
	pr_info("sov_iommu: mapped %zu bytes at IOVA %#llx (prot %#x)\n", size,
		(unsigned long long)s->iova, prot);
	return 0;
}

/* Unmap and free. After this the device faults on DMA again. */
static void sov_revoke_dma(struct sov_iommu *s)
{
	size_t bytes, unmapped;

	if (!s->mapped)
		return;

	bytes = PAGE_ALIGN(s->size);
	unmapped = iommu_unmap(s->domain, s->iova, bytes);
	if (unmapped != bytes)
		pr_warn("sov_iommu: unmapped %zu of %zu bytes\n", unmapped, bytes);

	free_pages((unsigned long)s->buffer, get_order(bytes));
	s->buffer = NULL;
	s->mapped = false;
	pr_info("sov_iommu: revoked; device DMA faults again\n");
}

/* --- sysfs interface, so a test can map and unmap at run time ---------------------------- */

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	phys_addr_t at_base, at_zero;

	(void)kobj;
	(void)attr;

	if (!sov.domain)
		return scnprintf(buf, PAGE_SIZE, "domain=none\n");

	at_zero = iommu_iova_to_phys(sov.domain, 0);
	at_base = iommu_iova_to_phys(sov.domain, SOV_IOVA_BASE);

	return scnprintf(buf, PAGE_SIZE,
			 "device=%s\ndomain=present\ndevice_in_our_domain=%d\ndevice_group=%d\n"
			 "mapped=%d\niova=%#llx\nsize=%zu\n"
			 "phys_at_0=%pa\nphys_at_iova=%pa\n",
			 pci_name(sov.pdev),
			 iommu_get_domain_for_dev(&sov.pdev->dev) == sov.domain ? 1 : 0,
			 iommu_group_id(sov.group),
			 sov.mapped ? 1 : 0,
			 (unsigned long long)sov.iova, sov.size, &at_zero, &at_base);
}

static ssize_t map_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			 size_t count)
{
	unsigned int size = 0;
	char dir[8] = "read";
	int ret;

	(void)kobj;
	(void)attr;

	if (sscanf(buf, "%u %7s", &size, dir) < 1)
		return -EINVAL;

	ret = sov_grant_dma(&sov, size, !strcmp(dir, "write") || !strcmp(dir, "rw"));
	if (ret)
		return ret;
	return count;
}

static ssize_t unmap_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			   size_t count)
{
	(void)kobj;
	(void)attr;
	(void)buf;

	sov_revoke_dma(&sov);
	return count;
}

/* --- self test: make the device actually try, and see what happens ------------------------
 *
 * Every other check in this file reads a translation table. That is evidence, but it is the
 * module's own view of the world. This test asks the hardware: program the device's DMA engine
 * to copy memory, and see whether the copy lands.
 *
 * The edu device (QEMU hw/misc/edu.c) copies through an internal 4 KiB buffer at
 * DMA_START (0x40000). A RAM->RAM copy is two commands:
 *
 *   1. dir=0 (from PCI): src=IOVA to read, dst=DMA_START, cnt=n   -> fills the device buffer
 *   2. dir=1 (to PCI):   src=DMA_START, dst=IOVA to write, cnt=n  -> drains it to memory
 *
 * Both commands run on a 100 ms virtual-clock timer, so the test sleeps between them.
 *
 * The two halves use the same buffers and the same commands. In the first, both IOVAs are
 * mapped and the copy must land. In the second the destination is unmapped, and the copy must
 * be dropped by the IOMMU. A device that is not contained writes in both cases.
 */

#define EDU_IDENT 0x00
#define EDU_DMA_SRC 0x80
#define EDU_DMA_DST 0x88
#define EDU_DMA_CNT 0x90
#define EDU_DMA_CMD 0x98

#define EDU_DMA_RUN 0x1
#define EDU_DMA_TO_PCI 0x2
#define EDU_BUF_START 0x40000

#define SELFTEST_SRC_IOVA 0x200000UL
#define SELFTEST_DST_IOVA 0x300000UL
#define SELFTEST_LEN 4096

struct sov_selftest {
	void *src;
	void *dst;
	int pass;
	int fail;
};

static void sov_check(struct sov_selftest *t, bool ok, const char *msg)
{
	if (ok) {
		pr_info("sov_iommu:   ok   %s\n", msg);
		t->pass++;
	} else {
		pr_err("sov_iommu:   FAIL %s\n", msg);
		t->fail++;
	}
}

/* Ask the device to copy SELFTEST_LEN bytes from src_iova to dst_iova. */
static void sov_edu_copy(void __iomem *bar, dma_addr_t src_iova, dma_addr_t dst_iova)
{
	/* Load: read src_iova into the device buffer. */
	writel(lower_32_bits(src_iova), bar + EDU_DMA_SRC);
	writel(EDU_BUF_START, bar + EDU_DMA_DST);
	writel(SELFTEST_LEN, bar + EDU_DMA_CNT);
	wmb();
	writel(EDU_DMA_RUN, bar + EDU_DMA_CMD);
	msleep(200);

	/* Store: write the device buffer out to dst_iova. */
	writel(EDU_BUF_START, bar + EDU_DMA_SRC);
	writel(lower_32_bits(dst_iova), bar + EDU_DMA_DST);
	writel(SELFTEST_LEN, bar + EDU_DMA_CNT);
	wmb();
	writel(EDU_DMA_RUN | EDU_DMA_TO_PCI, bar + EDU_DMA_CMD);
	msleep(200);
}

static int sov_selftest_run(struct sov_iommu *s, void __iomem *bar)
{
	struct sov_selftest t = { 0 };
	bool clean;
	int i, ret = 0;

	t.src = (void *)__get_free_page(GFP_KERNEL);
	t.dst = (void *)__get_free_page(GFP_KERNEL);
	if (!t.src || !t.dst) {
		ret = -ENOMEM;
		goto out_free;
	}

	/* --- half one: both IOVAs mapped. The copy must land. ------------------------------- */
	memset(t.src, 0xAA, SELFTEST_LEN);
	memset(t.dst, 0x00, SELFTEST_LEN);

	ret = iommu_map(s->domain, SELFTEST_SRC_IOVA, virt_to_phys(t.src), SELFTEST_LEN,
			IOMMU_READ, GFP_KERNEL);
	if (ret) {
		pr_err("sov_iommu: selftest: map src failed: %d\n", ret);
		goto out_free;
	}
	ret = iommu_map(s->domain, SELFTEST_DST_IOVA, virt_to_phys(t.dst), SELFTEST_LEN,
			IOMMU_READ | IOMMU_WRITE, GFP_KERNEL);
	if (ret) {
		pr_err("sov_iommu: selftest: map dst failed: %d\n", ret);
		iommu_unmap(s->domain, SELFTEST_SRC_IOVA, SELFTEST_LEN);
		goto out_free;
	}

	sov_edu_copy(bar, SELFTEST_SRC_IOVA, SELFTEST_DST_IOVA);

	sov_check(&t, ((u8 *)t.dst)[0] == 0xAA && ((u8 *)t.dst)[SELFTEST_LEN - 1] == 0xAA,
		  "mapped: device DMA reached the buffer (copy landed)");
	pr_info("sov_iommu:   info dst[0]=%#x dst[last]=%#x\n",
		((u8 *)t.dst)[0], ((u8 *)t.dst)[SELFTEST_LEN - 1]);

	/* --- half two: destination unmapped. The same copy must be dropped. ---------------- */
	iommu_unmap(s->domain, SELFTEST_DST_IOVA, SELFTEST_LEN);
	memset(t.src, 0x55, SELFTEST_LEN);
	memset(t.dst, 0x00, SELFTEST_LEN);
	mb();

	sov_edu_copy(bar, SELFTEST_SRC_IOVA, SELFTEST_DST_IOVA);

	clean = true;
	for (i = 0; i < SELFTEST_LEN; i++) {
		if (((u8 *)t.dst)[i] != 0x00) {
			clean = false;
			break;
		}
	}
	sov_check(&t, clean, "unmapped: the same DMA was dropped, buffer untouched");
	pr_info("sov_iommu:   info dst[0]=%#x after the unmapped attempt\n", ((u8 *)t.dst)[0]);

	iommu_unmap(s->domain, SELFTEST_SRC_IOVA, SELFTEST_LEN);

	pr_info("sov_iommu: selftest %s (%d passed, %d failed)\n",
		t.fail ? "FAILED" : "passed", t.pass, t.fail);
	if (t.fail)
		ret = -EIO;

out_free:
	if (t.src)
		free_page((unsigned long)t.src);
	if (t.dst)
		free_page((unsigned long)t.dst);
	return ret;
}

static ssize_t selftest_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			      size_t count)
{
	void __iomem *bar;
	int ret;

	(void)kobj;
	(void)attr;
	(void)buf;

	/* The device was detached from its driver on load, so nothing has enabled bus mastering.
 * Enable it deliberately: the test is only meaningful if the device is free to try. */
pci_set_master(sov.pdev);

bar = pci_iomap(sov.pdev, 0, 0);
	if (!bar) {
		pr_err("sov_iommu: selftest: cannot map BAR0\n");
		return -EIO;
	}

	if ((readl(bar + EDU_IDENT) & 0xff) != 0xed) {
		pr_err("sov_iommu: selftest: device at BAR0 is not edu; skipping\n");
		pci_iounmap(sov.pdev, bar);
		return -ENODEV;
	}

	ret = sov_selftest_run(&sov, bar);
	pci_iounmap(sov.pdev, bar);

	return ret ? ret : count;
}

static struct kobj_attribute sov_state_attr = __ATTR_RO(state);
static struct kobj_attribute sov_map_attr = __ATTR_WO(map);
static struct kobj_attribute sov_unmap_attr = __ATTR_WO(unmap);
static struct kobj_attribute sov_selftest_attr = __ATTR_WO(selftest);

static struct attribute *sov_attrs[] = {
	&sov_state_attr.attr,
	&sov_map_attr.attr,
	&sov_unmap_attr.attr,
	&sov_selftest_attr.attr,
	NULL,
};

static struct attribute_group sov_attr_group = {
	.attrs = sov_attrs,
};

static struct kobject *sov_kobj;

static char *bdf;
module_param(bdf, charp, 0444);
MODULE_PARM_DESC(bdf, "PCI address of the device to contain, e.g. 0000:00:04.0");

static int __init sov_iommu_init(void)
{
	int ret;

	sov.pdev = sov_find_device(bdf);
	if (!sov.pdev) {
		pr_err("sov_iommu: no device at %s\n", bdf ? bdf : "(bdf not set)");
		return -ENODEV;
	}

	ret = sov_isolate(&sov);
	if (ret)
		goto out_put;

	sov_kobj = kobject_create_and_add("sov_iommu", kernel_kobj);
	if (!sov_kobj) {
		ret = -ENOMEM;
		goto out_isolate;
	}

	ret = sysfs_create_group(sov_kobj, &sov_attr_group);
	if (ret) {
		pr_err("sov_iommu: sysfs group failed: %d\n", ret);
		goto out_kobj;
	}

	pr_info("sov_iommu: loaded\n");
	return 0;

out_kobj:
	kobject_put(sov_kobj);
	sov_kobj = NULL;
out_isolate:
	sov_revoke_dma(&sov);
	if (sov.domain) {
		iommu_detach_group(sov.domain, sov.group);
		iommu_domain_free(sov.domain);
		sov.domain = NULL;
	}
	if (sov.group) {
		iommu_group_put(sov.group);
		sov.group = NULL;
	}
out_put:
	pci_dev_put(sov.pdev);
	sov.pdev = NULL;
	return ret;
}

static void __exit sov_iommu_exit(void)
{
	if (sov_kobj) {
		sysfs_remove_group(sov_kobj, &sov_attr_group);
		kobject_put(sov_kobj);
	}

	sov_revoke_dma(&sov);

	if (sov.domain) {
		iommu_detach_group(sov.domain, sov.group);
		iommu_domain_free(sov.domain);
	}
	if (sov.group)
		iommu_group_put(sov.group);
	if (sov.pdev)
		pci_dev_put(sov.pdev);

	pr_info("sov_iommu: unloaded\n");
}

module_init(sov_iommu_init);
module_exit(sov_iommu_exit);

/* GPL: the IOMMU API is EXPORT_SYMBOL_GPL. The project is AGPL-3.0-only; a kernel module
 * cannot use GPL-only symbols under any other license, so this file is GPL and the userspace
 * crates remain AGPL. Stated here rather than left as a surprise. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sovereign IOMMU containment for a plug-in PCI device");

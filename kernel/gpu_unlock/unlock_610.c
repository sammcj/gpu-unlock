// SPDX-License-Identifier: GPL-2.0-only
/*
 * Pre-driver V67 unlock, run before the stock driver binds: FWSEC-FRTS from
 * the board ROM, Booter with the V67 signature, the SS0/SS1 selector writes, then
 * FLR so the stock driver starts from a clean, halted GSP. After resume from
 * suspend it runs again on the card nvidia has suspended, before nvidia resumes it.
 */
#include <linux/aperture.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>

#include "diagnostic.h"
#include "falcon.h"
#include "gfw_eval.h"
#include "prep_610.h"
#include "recipes.h"
#include "registers.h"
#include "payload_610.h"
#include "unlock_610.h"
#include "vbios_610.h"

enum gu_lifecycle { GU_ALLOCATED, GU_PUBLISHED, GU_ACTIVE, GU_STOCK, GU_QUIESCED };
struct unlock_transaction_page {
	void *cpu;
	dma_addr_t dma;
};

struct unlock_transaction_work {
	struct pci_dev *pdev;
	bool resume;	/* bound to nvidia, which suspended it before sleep */
	void __iomem *bar;
	resource_size_t bar_len;
	u16 original_cmd;
	bool cmd_valid;
	bool enabled;
	bool region;
	bool mapped;
	bool master;
	const struct firmware *booter_fw; /* borrowed immutable shared assets */
	const struct firmware *loader_fw;
	const struct firmware *gsp_fw;	/* borrowed from gpu_unlock_610_shared */
	const struct firmware *boot_fw;
	struct gpu_unlock_span image_span, sig_span;
	struct gpu_unlock_layout_in layout_in;
	struct gpu_unlock_layout_out layout;
	struct gpu_unlock_boot_desc boot_desc;
	struct gpu_unlock_radix_plan radix;
	struct unlock_transaction_page *pages;
	u32 page_count, pages_allocated;
	void *boot_cpu;
	dma_addr_t boot_dma;
	void *booter_cpu;
	dma_addr_t booter_dma;
	u32 booter_image_size;
	struct gpu_unlock_booter_hdr booter_hdr;
	void *payload_cpu;
	dma_addr_t payload_dma;
	void *stock_cpu;
	dma_addr_t stock_dma;
	u64 stock_size;
	void *meta_cpu;
	dma_addr_t meta_dma;
	u64 *streaming_ptr;
	u64 streaming_before;
	u64 coherent_before;
	bool streaming_set;
	bool coherent_set;
	enum gu_lifecycle state;
	const struct gu_card *card;
	const struct gpu_unlock_610_fw_desc *load;
	const struct gu_family_writes *family;
	size_t write_index;
	unsigned int attempt;
	u32 frts_lo, frts_hi;
	bool frts_saved, invocation_halted, fresh, cleanup_complete;
	struct gu_falcon_evidence launch, fwsec_launch;
	u32 target_before, target_after, mailbox0, mailbox1;
	bool masks_saved;
	bool firmware_started;
	bool retained;
	bool error_reported;
	u32 plm_entry;
	u32 bars[6];
	void *fwsec_cpu;
	dma_addr_t fwsec_dma;
	u32 fwsec_size;
	u32 last_offset, last_value;
	bool last_valid;
	u32 last_pci_offset, last_pci_value;
	int last_pci_error;
	bool last_pci_cap;
};

static int unlock_transaction_result(struct unlock_transaction_work *work, int error,
			  const char *function, unsigned int line)
{
	if (error && !work->error_reported) {
		work->error_reported = true;
		dev_err(&work->pdev->dev,
			"failure unlock_610.c:%u %s error=%d last_mmio=%#x value=%#x valid=%u mapped=%u master=%u firmware_started=%u quiesced=%u pages=%u/%u\n",
			line, function, error, work->last_offset, work->last_value,
			work->last_valid, work->mapped, work->master, work->firmware_started,
			(work->state == GU_QUIESCED), work->pages_allocated, work->page_count);
		dev_err(&work->pdev->dev, "last PCI sample: capability=%u offset=%#x value=%#x result=%d\n",
			work->last_pci_cap, work->last_pci_offset, work->last_pci_value, work->last_pci_error);
	}
	return error;
}
#define GU_RESULT(result) unlock_transaction_result(work, (result), __func__, __LINE__)

static int diag_pci_word(struct unlock_transaction_work *work, bool cap, int offset, u16 *value)
{
	int ret;
	*value = 0xffff;
	ret = cap ? pcie_capability_read_word(work->pdev, offset, value) :
		pci_read_config_word(work->pdev, offset, value);
	work->last_pci_cap = cap;
	work->last_pci_offset = offset;
	work->last_pci_value = *value;
	work->last_pci_error = ret;
	return ret;
}

static int diag_pci_dword(struct unlock_transaction_work *work, bool cap, int offset, u32 *value)
{
	int ret;
	*value = ~0u;
	ret = cap ? pcie_capability_read_dword(work->pdev, offset, value) :
		pci_read_config_dword(work->pdev, offset, value);
	work->last_pci_cap = cap;
	work->last_pci_offset = offset;
	work->last_pci_value = *value;
	work->last_pci_error = ret;
	return ret;
}

/* The config-space vendor/device dword this card answered at enumeration. */
static u32 pci_identity(const struct pci_dev *pdev)
{
	return (u32)pdev->device << 16 | pdev->vendor;
}

static void *diag_dma_alloc(struct unlock_transaction_work *work, const char *name,
			   size_t size, dma_addr_t *dma, unsigned int flags)
{
	void *memory = dma_alloc_coherent(&work->pdev->dev, size, dma, flags);
	if (!memory)
		dev_err(&work->pdev->dev, "DMA allocation failed: asset=%s bytes=%zu pages_allocated=%u requested=%u\n",
			name, size, work->pages_allocated, work->page_count);
	return memory;
}

static int check_devres_empty(struct unlock_transaction_work *work, const char *phase)
{
	struct device *dev = &work->pdev->dev;
	unsigned long flags;
	bool empty;

	/* The caller also holds the device lock across the whole transaction. */
	spin_lock_irqsave(&dev->devres_lock, flags);
	empty = list_empty(&dev->devres_head);
	spin_unlock_irqrestore(&dev->devres_lock, flags);
	dev_dbg(dev, "driver probe resources: phase=%s empty=%u\n", phase, empty);
	return GU_RESULT(empty ? 0 : -EBUSY);
}

static int read_bar(struct unlock_transaction_work *work, u32 offset, u32 *value)
{
	work->last_offset = offset;
	work->last_valid = false;
	if (!work->mapped || offset > work->bar_len || work->bar_len - offset < 4)
		return GU_RESULT(-EINVAL);
	*value = readl(work->bar + offset);
	work->last_value = *value;
	work->last_valid = true;
	return 0;
}

static void write_bar(struct unlock_transaction_work *work, u32 offset, u32 value)
{
	writel(value, work->bar + offset);
}

static int transport_read(void *context, u32 offset, u32 *value)
{
	return read_bar(context, offset, value);
}
static void transport_write(void *context, u32 offset, u32 value)
{
	write_bar(context, offset, value);
}
static struct gu_falcon_io falcon_io(struct unlock_transaction_work *work)
{
	return (struct gu_falcon_io) {
		.dev = &work->pdev->dev, .context = work,
		.read = transport_read, .write = transport_write,
	};
}

static bool inaccessible(u32 value)
{
	return value == ~0u || (value & 0xffff0000u) == 0xbadf0000u;
}

static int patch_booter(struct unlock_transaction_work *work)
{
	const u8 *data = work->booter_fw->data;
	u32 fuse_raw, fuse_ver;
	u32 index = work->booter_hdr.ucode_id - 1;

	if (read_bar(work, GU_FUSE_SEC2_UCODE1 + index * 4, &fuse_raw))
		return GU_RESULT(-EIO);
	fuse_ver = gpu_unlock_fuse_version(fuse_raw);
	dev_dbg(&work->pdev->dev, "Booter signature: fuse_raw=%#x version=%u signatures=%u size=%u\n",
		fuse_raw, fuse_ver, work->booter_hdr.num_sigs, work->booter_hdr.sig_bytes);
	return GU_RESULT(gpu_unlock_booter_patch(work->booter_cpu, work->booter_image_size,
				       &work->booter_hdr,
				       data + 72 + work->booter_image_size,
				       work->booter_hdr.sig_bytes, fuse_ver));
}

static void free_coherent(struct unlock_transaction_work *work)
{
	u32 i;

	for (i = 0; i < work->pages_allocated; i++)
		dma_free_coherent(&work->pdev->dev, GU_RADIX_PAGE,
				  work->pages[i].cpu, work->pages[i].dma);
	kvfree(work->pages);
	work->pages = NULL;
	work->pages_allocated = 0;
	if (work->boot_cpu)
		dma_free_coherent(&work->pdev->dev, work->boot_desc.image_size,
				  work->boot_cpu, work->boot_dma);
	work->boot_cpu = NULL;
	if (work->fwsec_cpu) {
		dma_free_coherent(&work->pdev->dev, work->fwsec_size,
				  work->fwsec_cpu, work->fwsec_dma);
		work->fwsec_cpu = NULL;
	}
	if (work->booter_cpu)
		dma_free_coherent(&work->pdev->dev, GU_BOOTER_IMAGE_SIZE,
				  work->booter_cpu, work->booter_dma);
	if (work->payload_cpu)
		dma_free_coherent(&work->pdev->dev, GU_PAYLOAD_SIZE, work->payload_cpu,
				  work->payload_dma);
	if (work->stock_cpu)
		dma_free_coherent(&work->pdev->dev, work->stock_size,
				  work->stock_cpu, work->stock_dma);
	if (work->meta_cpu)
		dma_free_coherent(&work->pdev->dev, GU_WPR_META_SIZE,
				  work->meta_cpu, work->meta_dma);
	work->booter_cpu = NULL;
	work->payload_cpu = NULL;
	work->stock_cpu = NULL;
	work->meta_cpu = NULL;
}

static int unlock_transaction_unwind(struct unlock_transaction_work *work)
{
	u16 now, want;
	int ret = 0;

	/* A timeout never authorizes freeing firmware-visible memory. */
	if (work->firmware_started && work->state != GU_QUIESCED) {
		pci_clear_master(work->pdev);
		work->master = false;
		work->retained = true;
		ret = diag_pci_word(work, false, PCI_COMMAND, &now);
		dev_err(&work->pdev->dev, "handover refused: incomplete transaction; BME_off=%u command=%#x config_result=%d; BAR ownership and DMA buffers retained until power off\n",
			!ret && now != 0xffff && !(now & PCI_COMMAND_MASTER), now, ret);
		return GU_RESULT(-EBUSY);
	}
	if (work->master) {
		pci_clear_master(work->pdev);
		work->master = false;
	}
	if (work->mapped) {
		pci_iounmap(work->pdev, work->bar);
		work->bar = NULL;
		work->mapped = false;
	}
	if (work->region) {
		pci_release_region(work->pdev, 0);
		work->region = false;
	}
	if (work->enabled) {
		pci_disable_device(work->pdev);
		work->enabled = false;
	}
	free_coherent(work);
	/* Match the driver core's entry condition, not just BAR/mask cleanup.
	 * Never release unrelated resources to make this check pass. A bound
	 * driver keeps its own resources and is not probed again.
	 */
	if (!work->resume && check_devres_empty(work, "handoff"))
		ret = -EBUSY;
	if (work->streaming_set && work->streaming_ptr) {
		if (work->pdev->dev.dma_mask != work->streaming_ptr)
			return GU_RESULT(-EIO);
		if (dma_set_mask(&work->pdev->dev, work->streaming_before) ||
		    *work->streaming_ptr != work->streaming_before)
			ret = -EIO;
		dev_dbg(&work->pdev->dev, "restore streaming mask: actual=%#llx expected=%#llx\n",
			(unsigned long long)*work->streaming_ptr, (unsigned long long)work->streaming_before);
	}
	if (work->coherent_set) {
		if (dma_set_coherent_mask(&work->pdev->dev, work->coherent_before) ||
		    work->pdev->dev.coherent_dma_mask != work->coherent_before)
			ret = -EIO;
		dev_dbg(&work->pdev->dev, "restore coherent mask: actual=%#llx expected=%#llx\n",
			(unsigned long long)work->pdev->dev.coherent_dma_mask,
			(unsigned long long)work->coherent_before);
	}
	if (!work->cmd_valid)
		return GU_RESULT(ret);
	if (diag_pci_word(work, false, PCI_COMMAND, &now) || now == 0xffff)
		return GU_RESULT(-ENODEV);
	want = gpu_unlock_command_restore(work->original_cmd, now);
	if (want != now && pci_write_config_word(work->pdev, PCI_COMMAND, want))
		return GU_RESULT(-EIO);
	/* nvidia does not set BME again on resume. pci_clear_master() before the
	 * FLR also cleared the PCI core's record of it; set both back. */
	if (work->resume && (want & PCI_COMMAND_MASTER))
		pci_set_master(work->pdev);
	if (diag_pci_word(work, false, PCI_COMMAND, &now))
		return GU_RESULT(-EIO);
	dev_dbg(&work->pdev->dev, "restore PCI command: actual=%#x original=%#x mask=%#x\n",
		now, work->original_cmd, GU_PCI_COMMAND_MEMORY | GU_PCI_COMMAND_MASTER);
	if ((now & (GU_PCI_COMMAND_MEMORY | GU_PCI_COMMAND_MASTER)) !=
	    (work->original_cmd & (GU_PCI_COMMAND_MEMORY | GU_PCI_COMMAND_MASTER)))
		return GU_RESULT(-EIO);
	return GU_RESULT(ret);
}

static int unlock_transaction_layout(struct unlock_transaction_work *work)
{
	struct gpu_unlock_layout_in *in = &work->layout_in;
	u32 mb, vga, lo, hi, plm;
	int ret;

	if (read_bar(work, GU_GFW_FB_SIZE_OFFSET, &mb) || !mb || mb == ~0u ||
	    read_bar(work, GU_VGA_WORKSPACE_BASE_OFFSET, &vga) || vga == ~0u ||
	    read_bar(work, GU_MMU_LOCK_CFG_PLM_OFFSET, &plm) || plm == ~0u || !(plm & 1) ||
	    read_bar(work, GU_MMU_LOCK_ADDR_LO_OFFSET, &lo) || lo == ~0u ||
	    read_bar(work, GU_MMU_LOCK_ADDR_HI_OFFSET, &hi) || hi == ~0u)
		return GU_RESULT(-ENODEV);
	/* Keep the cold board inputs in the USB kernel log even on layout failure.
	 * Register values after NVIDIA binds cannot reconstruct this state. */
	dev_dbg(&work->pdev->dev,
		 "layout inputs: fb_mb=%#x vga=%#x mmu_plm=%#x mmu_lo=%#x mmu_hi=%#x image=%llu boot=%u\n",
		 mb, vga, plm, lo, hi, (unsigned long long)work->image_span.size,
		 work->boot_desc.image_size);
	in->usable_fb = (u64)mb << 20;
	if (in->usable_fb < 256ull << 20) {
		dev_err(&work->pdev->dev, "layout rejected: usable FB below 256 MiB\n");
		return GU_RESULT(-ERANGE);
	}
	/* kgspPopulateWprMeta_TU102: PRAMIN is the top 1 MiB fallback. */
	in->vga_base = in->usable_fb - (1ull << 20);
	if (vga & (1u << 3)) {
		in->vga_base = (u64)(vga >> 8) << 16;
		if (in->vga_base < in->usable_fb - (1ull << 20))
			in->vga_base = in->usable_fb - 0x20000;
	}
	if (in->vga_base >= in->usable_fb) {
		dev_err(&work->pdev->dev, "layout rejected: VGA base at or above usable FB\n");
		return GU_RESULT(-ERANGE);
	}
	in->mmu_lock_low = (u64)(lo >> 4) << 12;
	{
		/* VAL is bits 31:4; the address is that field shifted by 12.
		 * memmgrBlockMemLockedMemory_GA100 only treats the lock as the
		 * VBIOS end-of-FB reservation when its exclusive high address is
		 * the FB top. A lock elsewhere is not that reservation. GA102
		 * has no scrubber, so WPR must stay in the pre-scrubbed top. */
		u64 mmu_hi = (u64)(hi >> 4) << 12;
		u64 mmu_top = mmu_hi > ~0ull - 0xffffull ? ~0ull :
			(mmu_hi + 0xffffull) & ~0xffffull;
		bool top_lock;

		in->mmu_lock_valid = mmu_hi >= in->mmu_lock_low;
		top_lock = in->mmu_lock_valid && (mmu_top >> 20) == (in->usable_fb >> 20);
		dev_dbg(&work->pdev->dev,
			 "layout mmu: lo=%#llx hi=%#llx hi_exclusive=%#llx constrain=%u\n",
			 (unsigned long long)in->mmu_lock_low, (unsigned long long)mmu_hi,
			 (unsigned long long)mmu_top, top_lock);
		if (!top_lock) {
			dev_dbg(&work->pdev->dev,
				 "mmu lock ignored: high address is not the FB top\n");
			in->mmu_lock_valid = false;
		}
	}
	in->frts_size = 1ull << 20;
	in->boot_size = work->boot_desc.image_size;
	in->image_size = work->image_span.size;
	in->nonwpr_size = 1ull << 20;
	/* GA102's supported minimum heap; no GSP-RM clients are started here. */
	in->heap_request = 88ull << 20;
	ret = gpu_unlock_layout(in, &work->layout);
	dev_dbg(&work->pdev->dev,
		 "layout decoded: fb=%#llx vga=%#llx mmu_valid=%u mmu_low=%#llx frts=%#llx heap=%#llx result=%d\n",
		 (unsigned long long)in->usable_fb, (unsigned long long)in->vga_base,
		 in->mmu_lock_valid, (unsigned long long)in->mmu_lock_low,
		 (unsigned long long)in->frts_size, (unsigned long long)in->heap_request, ret);
	if (ret) {
		dev_err(&work->pdev->dev, "layout rejected: reservation calculation (%d)\n", ret);
		return GU_RESULT(ret);
	}
	dev_dbg(&work->pdev->dev,
		 "layout ranges: nonwpr=%#llx wpr=%#llx heap=%#llx gsp=%#llx boot=%#llx frts=%#llx end=%#llx scrub_floor=%#llx\n",
		 (unsigned long long)work->layout.nonwpr_start,
		 (unsigned long long)work->layout.wpr_start,
		 (unsigned long long)work->layout.heap_offset,
		 (unsigned long long)work->layout.gsp_offset,
		 (unsigned long long)work->layout.boot_offset,
		 (unsigned long long)work->layout.frts_offset,
		 (unsigned long long)work->layout.wpr_end,
		 (unsigned long long)(in->usable_fb - (256ull << 20)));
	/* GA102 has no scrubber: all reservations must fit the pre-scrubbed top. */
	if (work->layout.nonwpr_start < in->usable_fb - (256ull << 20)) {
		dev_err(&work->pdev->dev, "layout rejected: reservations below pre-scrubbed top 256 MiB\n");
		return GU_RESULT(-ERANGE);
	}
	return 0;
}

static int unlock_transaction_radix(struct unlock_transaction_work *work)
{
	const struct gpu_unlock_radix_plan *r = &work->radix;
	u64 *addresses;
	u32 i, level, first = 0;
	int ret = 0;

	work->page_count = r->table_pages + r->pages[3];
	work->pages = kvcalloc(work->page_count, sizeof(*work->pages), GFP_KERNEL);
	addresses = kvcalloc(work->page_count, sizeof(*addresses), GFP_KERNEL);
	if (!work->pages || !addresses) {
		kvfree(addresses);
		return GU_RESULT(-ENOMEM);
	}
	for (i = 0; i < work->page_count; i++) {
		struct unlock_transaction_page *page = &work->pages[i];

		page->cpu = diag_dma_alloc(work, "radix-page", GU_RADIX_PAGE,
					       &page->dma, GFP_KERNEL);
		if (!page->cpu) {
			ret = -ENOMEM;
			goto out;
		}
		work->pages_allocated++;
		addresses[i] = page->dma;
		memset(page->cpu, 0, GU_RADIX_PAGE);
		if (i >= r->table_pages) {
			u64 offset = (i - r->table_pages) * GU_RADIX_PAGE;
			size_t n = min_t(u64, GU_RADIX_PAGE, work->image_span.size - offset);

			memcpy(page->cpu, work->gsp_fw->data + work->image_span.offset + offset, n);
		}
	}
	for (level = 0; level < 3; level++) {
		u32 child = first + r->pages[level];

		for (i = 0; i < r->pages[level]; i++) {
			u32 at = i * (GU_RADIX_PAGE / 8);
			u32 n = min_t(u64, GU_RADIX_PAGE / 8, r->pages[level + 1] - at);

			ret = gpu_unlock_radix_page(work->pages[first + i].cpu,
						    addresses + child + at, n);
			if (ret)
				goto out;
		}
		first = child;
	}
out:
	kvfree(addresses);
	return GU_RESULT(ret);
}

static int unlock_transaction_claim(struct unlock_transaction_work *work)
{
	u16 command, pmcsr;
	u32 cap;
	unsigned int i;
	int ret;

	dev_dbg(&work->pdev->dev, "claim: power=%d pm_cap=%#x flags=%#x\n",
		work->pdev->current_state, work->pdev->pm_cap, work->pdev->dev_flags);
	/* Older kernels (seen on 6.8 and 6.14) leave a device no driver has
	 * enabled at PCI_UNKNOWN. Accept that only when PMCSR confirms D0. */
	if ((work->pdev->current_state != PCI_D0 &&
	     (work->pdev->current_state != PCI_UNKNOWN || !work->pdev->pm_cap)) ||
	    (work->pdev->pm_cap &&
	     (diag_pci_word(work, false, work->pdev->pm_cap + PCI_PM_CTRL, &pmcsr) ||
	      (pmcsr & PCI_PM_CTRL_STATE_MASK) != PCI_D0)))
		return GU_RESULT(-EOPNOTSUPP);
	if ((work->pdev->dev_flags & PCI_DEV_FLAGS_NO_FLR_RESET) ||
	    !pci_is_pcie(work->pdev) ||
	    diag_pci_dword(work, true, PCI_EXP_DEVCAP, &cap) ||
	    !(cap & PCI_EXP_DEVCAP_FLR))
		return GU_RESULT(-EOPNOTSUPP);
	if (diag_pci_word(work, false, PCI_COMMAND, &command) || command == 0xffff)
		return GU_RESULT(-ENODEV);
	work->original_cmd = command;
	work->cmd_valid = true;
	/* Some firmware (Supermicro X11 AMI) hands every card over with BME set,
	 * whatever its option ROM and bus master settings. No driver is bound,
	 * and the WPR2 check still refuses a card that one has initialised. */
	if (command & PCI_COMMAND_MASTER) {
		command &= ~PCI_COMMAND_MASTER;
		if (pci_write_config_word(work->pdev, PCI_COMMAND, command) ||
		    diag_pci_word(work, false, PCI_COMMAND, &command) ||
		    command == 0xffff || (command & PCI_COMMAND_MASTER))
			return GU_RESULT(-EBUSY);
		dev_dbg(&work->pdev->dev, "claim: cleared %s BME\n",
			 work->resume ? "driver" : "firmware");
		/* Firmware's BME stays off; the suspended driver gets its own back. */
		if (!work->resume)
			work->original_cmd = command;
	}
	dev_dbg(&work->pdev->dev, "claim: command=%#x capability=%#x BAR_mask=%#x\n",
		command, cap, pci_select_bars(work->pdev, IORESOURCE_MEM));
	/* Only BAR0 is mapped. On the display card the firmware framebuffer keeps
	 * BAR1 until just before the FLR, as it does while the stock driver boots.
	 * After resume nvidia keeps the BAR0 region it requested at probe.
	 */
	if (!work->resume) {
		ret = pci_request_region(work->pdev, 0, "gpu_unlock");
		if (ret)
			return GU_RESULT(ret);
		work->region = true;
	}
	if (!(command & PCI_COMMAND_MEMORY)) {
		ret = pci_enable_device_mem(work->pdev);
		if (ret)
			return GU_RESULT(ret);
		work->enabled = true;
	}
	work->bar_len = pci_resource_len(work->pdev, 0);
	if (work->bar_len < GU_SEC2_FALCON2_BASE + GU_FALCON2_WINDOW_SIZE)
		return GU_RESULT(-EINVAL);
	for (i = 0; i < ARRAY_SIZE(work->bars); i++)
		if (diag_pci_dword(work, false, PCI_BASE_ADDRESS_0 + i * 4, &work->bars[i]))
			return GU_RESULT(-EIO);
	ret = pci_save_state(work->pdev);
	if (ret)
		return GU_RESULT(ret);
	if (work->mapped)
		return 0;
	work->bar = pci_iomap(work->pdev, 0, 0);
	if (!work->bar)
		return GU_RESULT(-ENOMEM);
	work->mapped = true;
	return 0;
}

static int unlock_transaction_dma(struct unlock_transaction_work *work)
{
	struct device *dev = &work->pdev->dev;

	if (!dev->dma_mask || work->masks_saved)
		return GU_RESULT(-EINVAL);
	work->masks_saved = true;
	work->streaming_ptr = dev->dma_mask;
	work->streaming_before = *dev->dma_mask;
	work->coherent_before = dev->coherent_dma_mask;
	dev_dbg(dev, "DMA masks: streaming=%#llx coherent=%#llx requested=%#llx\n",
		(unsigned long long)work->streaming_before, (unsigned long long)work->coherent_before,
		(unsigned long long)DMA_BIT_MASK(32));
	work->streaming_set = true;
	if (GU_DIAG(dma_set_mask(dev, DMA_BIT_MASK(32))))
		return GU_RESULT(-EIO);
	work->coherent_set = true;
	if (GU_DIAG(dma_set_coherent_mask(dev, DMA_BIT_MASK(32))))
		return GU_RESULT(-EIO);
	work->booter_cpu = diag_dma_alloc(work, "booter", work->booter_image_size,
					      &work->booter_dma, GFP_KERNEL);
	if (!work->booter_cpu)
		return GU_RESULT(-ENOMEM);
	memcpy(work->booter_cpu, work->booter_fw->data + 72, work->booter_image_size);
	work->payload_cpu = diag_dma_alloc(work, "payload", GU_PAYLOAD_SIZE, &work->payload_dma, GFP_KERNEL);
	work->meta_cpu = diag_dma_alloc(work, "metadata", GU_WPR_META_SIZE, &work->meta_dma, GFP_KERNEL);
	if (!work->payload_cpu || !work->meta_cpu)
		return GU_RESULT(-ENOMEM);
	gu_payload_fill(work->payload_cpu, GU_FEAT_PLM_OFFSET, ~0u);
	work->stock_size = work->sig_span.size;
	work->stock_cpu = diag_dma_alloc(work, "stock-signature", work->stock_size, &work->stock_dma, GFP_KERNEL);
	work->boot_cpu = diag_dma_alloc(work, "boot-image", work->boot_desc.image_size, &work->boot_dma, GFP_KERNEL);
	if (!work->stock_cpu || !work->boot_cpu)
		return GU_RESULT(-ENOMEM);
	memcpy(work->stock_cpu, work->gsp_fw->data + work->sig_span.offset, work->stock_size);
	memcpy(work->boot_cpu, work->boot_fw->data, work->boot_desc.image_size);
	{
		int ret = patch_booter(work);

		return GU_RESULT(ret ? ret : unlock_transaction_radix(work));
	}
}

static int unlock_transaction_fwsec(struct unlock_transaction_work *work)
{
	static const struct gu_falcon_engine gsp = {
		.base = GU_GSP_BASE, .fbif = GU_GSP_FBIF_BASE, .falcon2 = GU_GSP_FALCON2_BASE,
		/* The WPR2 range check below proves FWSEC-FRTS ran. */
		.stale_halt_ok = true,
	};
	struct gu_falcon_io io = falcon_io(work);
	size_t mapped = 0;
	u8 *rom = NULL;
	struct gpu_unlock_fwsec fw;
	u32 fuse_raw, version, scratch, wpr_lo, wpr_hi;
	u16 command;
	u64 frts = work->layout.frts_offset;
	void *image = NULL;
	dma_addr_t image_dma = 0;
	int ret;

	/* kgspExtractVbiosFromRom_TU102 reads NV_PROM_DATA, up to 1 MiB.
	 * pci_map_rom stops at the PCI last-image flag and hides the VN extension. */
	dev_dbg(&work->pdev->dev, "FWSEC: reading PROM at %#x\n", GU_PROM_DATA_OFFSET);
	if (work->bar_len < GU_PROM_DATA_OFFSET + 0x1a)
		return GU_RESULT(-ENODEV);
	mapped = min_t(size_t, 1024 * 1024, work->bar_len - GU_PROM_DATA_OFFSET);
	rom = kvmalloc(mapped, GFP_KERNEL);
	if (!rom)
		return GU_RESULT(-ENOMEM);
	memcpy_fromio(rom, work->bar + GU_PROM_DATA_OFFSET, mapped);
	dev_dbg(&work->pdev->dev, "FWSEC: PROM bytes=%zu signature=%#x\n",
		 mapped, (unsigned int)(rom[0] | (rom[1] << 8)));
	ret = gpu_unlock_vbios_fwsec(rom, mapped, &fw);
	if (ret) {
		dev_err(&work->pdev->dev, "FWSEC-FRTS not found in board ROM (%d)\n", ret);
		goto out;
	}
	if ((fw.version == 2) != work->load->direct ||
	    (fw.version == 3 && fw.engine_mask != 0x400)) {
		dev_err(&work->pdev->dev, "FWSEC: unsupported GSP engine mask=%#x\n", fw.engine_mask);
		ret = -EOPNOTSUPP;
		goto out;
	}
	image = diag_dma_alloc(work, "fwsec", fw.image_size, &image_dma, GFP_KERNEL);
	if (!image) {
		ret = -ENOMEM;
		goto out;
	}
	work->fwsec_cpu = image;
	work->fwsec_dma = image_dma;
	work->fwsec_size = fw.image_size;
	memcpy(image, rom + fw.image_off, fw.image_size);
	ret = gpu_unlock_fwsec_patch_frts(image, &fw, frts);
	if (ret)
		goto out;
	if (fw.version == 3) {
		u32 sig_at = 0;
		if (!fw.ucode_id ||
		    read_bar(work, GU_FUSE_GSP_UCODE1 + (fw.ucode_id - 1) * 4, &fuse_raw)) {
			ret = -EIO;
			goto out;
		}
		version = gpu_unlock_fuse_version(fuse_raw);
		dev_dbg(&work->pdev->dev, "FWSEC fuse: raw=%#x version=%u\n", fuse_raw, version);
		ret = gpu_unlock_fwsec_sig_offset(fw.sig_versions, version, 384, &sig_at);
		if (ret)
			goto out;
		memcpy((u8 *)image + fw.data_off + fw.pkc_off, rom + fw.sig_off + sig_at, 384);
	}
	pci_set_master(work->pdev);
	work->master = true;
	if (diag_pci_word(work, false, PCI_COMMAND, &command) ||
	    command == 0xffff || !(command & PCI_COMMAND_MASTER)) {
		ret = -EIO;
		goto out;
	}
	/* Preserve conservative DMA retention from the moment FWSEC may access it,
	 * including reset/load failures. Launch evidence is observed separately. */
	work->firmware_started = true;
	if (fw.version == 2) {
		const struct gu_falcon_loader_image program = {
			.loader = work->loader_fw ? (const u32 *)work->loader_fw->data : NULL,
			.loader_size = work->loader_fw ? work->loader_fw->size : 0,
			.dma = image_dma, .data_off = fw.data_off,
			.imem_pa = fw.imem_pa, .imem_ns_size = fw.imem_ns_size,
			.imem_sec_pa = fw.imem_sec_pa, .imem_sec_size = fw.imem_sec_size,
			.dmem_size = fw.dmem_size,
		};
		ret = gu_falcon_loader(&io, &gsp, &program, &work->fwsec_launch);
	} else {
		const struct gu_falcon_hs_image program = {
			.dma = image_dma, .code_off = 0, .code_size = fw.imem_size,
			.code_va = fw.imem_va, .code_pa = fw.imem_pa,
			.data_off = fw.data_off, .data_size = fw.dmem_size,
			.data_pa = fw.dmem_pa, .sig_dmem = fw.pkc_off,
			.engine_mask = fw.engine_mask, .ucode_id = fw.ucode_id,
		};
		ret = gu_falcon_hs(&io, &gsp, &program, &work->fwsec_launch);
	}
	if (ret)
		goto out;
	if (read_bar(work, GU_ACR_SCRATCH_OFFSET, &scratch)) {
		ret = -EIO;
		goto out;
	}
	dev_dbg(&work->pdev->dev, "FWSEC result: scratch=%#x expected_hi16=0\n", scratch);
	if (scratch >> 16) {
		ret = -EIO;
		goto out;
	}
	if (read_bar(work, GU_WPR2_ADDR_LO_OFFSET, &wpr_lo) || wpr_lo == ~0u ||
	    read_bar(work, GU_WPR2_ADDR_HI_OFFSET, &wpr_hi) || wpr_hi == ~0u) {
		ret = -EIO;
		goto out;
	}
	dev_dbg(&work->pdev->dev, "FWSEC WPR2: low=%#x high=%#x expected_page=%#llx end=%#llx\n",
		wpr_lo, wpr_hi, (unsigned long long)(frts >> 12),
		(unsigned long long)work->layout.wpr_end);
	/* Match NVIDIA's initialized-WPR2 check as well as the expected low
	 * address. Never publish Booter metadata for disabled/alien WPR2. FWSEC
	 * sizes the region itself (0xe1000 bytes on GA102), so the high end is
	 * only bounded by the reserve. */
	if (!(wpr_hi >> 4) || (wpr_hi >> 4) < (wpr_lo >> 4) ||
	    ((u64)(wpr_hi >> 4) << 12) >= work->layout.wpr_end ||
	    (wpr_lo >> 4) != (u32)(frts >> 12))
		ret = -EIO;
	if (!ret) {
		work->frts_lo = wpr_lo;
		work->frts_hi = wpr_hi;
		work->frts_saved = true;
	}
out:
	/* Ownership transfers to work before publication, including failure paths. */
	kvfree(rom);
	return GU_RESULT(ret);
}

static int unlock_transaction_gfw(struct unlock_transaction_work *work)
{
	ktime_t deadline = ktime_add_us(ktime_get(), GU_GFW_TIMEOUT_US);
	int assessed = -EAGAIN;

	for (;;) {
		struct gpu_unlock_gfw_sample sample = { };
		u16 vendor = 0xffff;

		if (read_bar(work, GU_GFW_PLM_OFFSET, &sample.plm) ||
		    read_bar(work, GU_GFW_BOOT_OFFSET, &sample.boot) ||
		    read_bar(work, GU_GFW_CPUCTL_OFFSET, &sample.cpuctl))
			return GU_RESULT(-EIO);
		if (!diag_pci_word(work, false, PCI_VENDOR_ID, &vendor) &&
		    vendor != 0xffff)
			sample.config_ok = true;
		assessed = gpu_unlock_gfw_assess(&sample);
		if (!assessed) {
			u32 ss0, ss1, wpr_hi;

			if (read_bar(work, GU_FEAT_PLM_OFFSET, &work->plm_entry) ||
			    read_bar(work, GU_FEAT_SS0_OFFSET, &ss0) || ss0 == ~0u ||
			    read_bar(work, GU_FEAT_SS1_OFFSET, &ss1) || ss1 == ~0u ||
			    read_bar(work, GU_WPR2_ADDR_HI_OFFSET, &wpr_hi) || inaccessible(wpr_hi))
				return GU_RESULT(-ENODEV);
			dev_dbg(&work->pdev->dev, "entry: plm=%#x ss0=%#x ss1=%#x wpr2_hi=%#x\n",
				 work->plm_entry, ss0, ss1, wpr_hi);
			/* An open PLM means the card was already unlocked or not cold. */
			if (work->plm_entry == ~0u)
				return GU_RESULT(-EALREADY);
			/* WPR2 is down from power-on until FWSEC-FRTS runs. An enabled
			 * WPR2 means a driver has already used the card this power
			 * cycle; starting FWSEC and Booter again from here is untested.
			 */
			if (wpr_hi >> 4) {
				dev_err(&work->pdev->dev, "card already initialised since power on (WPR2 enabled); power off first\n");
				return GU_RESULT(-EBUSY);
			}
			return 0;
		}
		if (assessed != -EAGAIN)
			return GU_RESULT(assessed);
		if (ktime_compare(ktime_get(), deadline) >= 0)
			return GU_RESULT(-ETIMEDOUT);
		usleep_range(1000, 2000);
	}
}

/* After resume nvidia has suspended the card: its GSP-RM is down and BAR0's
 * region stays nvidia's, so BAR0 is mapped without a request. Nothing is
 * written until the card is known to have lost power: WPR2 down, the selectors
 * back at their power-on values and GFW finished again.
 */
static int unlock_transaction_suspended(struct unlock_transaction_work *work)
{
	u32 wpr_hi, ss0, ss1;
	u16 command;

	if (diag_pci_word(work, false, PCI_COMMAND, &command) || command == 0xffff ||
	    !(command & PCI_COMMAND_MEMORY))
		return GU_RESULT(-ENODEV);
	work->bar_len = pci_resource_len(work->pdev, 0);
	if (work->bar_len < GU_SEC2_FALCON2_BASE + GU_FALCON2_WINDOW_SIZE)
		return GU_RESULT(-EINVAL);
	work->bar = pci_iomap(work->pdev, 0, 0);
	if (!work->bar)
		return GU_RESULT(-ENOMEM);
	work->mapped = true;
	/* Read before GFW completes, so an unreadable value proves nothing yet. */
	if (read_bar(work, GU_WPR2_ADDR_HI_OFFSET, &wpr_hi) ||
	    read_bar(work, GU_FEAT_SS0_OFFSET, &ss0) ||
	    read_bar(work, GU_FEAT_SS1_OFFSET, &ss1))
		return GU_RESULT(-EIO);
	dev_dbg(&work->pdev->dev, "resume entry: wpr2_hi=%#x ss0=%#x ss1=%#x\n",
		 wpr_hi, ss0, ss1);
	if (!inaccessible(wpr_hi) && (wpr_hi >> 4)) {
		dev_dbg(&work->pdev->dev, "resume: GSP-RM already running (WPR2 enabled); card left as is\n");
		return -EBUSY;
	}
	/* Sleep that kept the card powered (suspend to idle, an aborted suspend). */
	if (ss0 == GU_SS0_UNLOCK && ss1 == GU_SS1_UNLOCK)
		return -EALREADY;
	return unlock_transaction_gfw(work);
}

static int unlock_transaction_boot(struct unlock_transaction_work *work)
{
	static const struct gu_falcon_engine sec2 = {
		.base = GU_SEC2_BASE, .fbif = GU_SEC2_FBIF_BASE, .falcon2 = GU_SEC2_FALCON2_BASE,
	};
	const struct gpu_unlock_booter_hdr *h = &work->booter_hdr;
	struct gu_falcon_io io = falcon_io(work);
	int ret;
	u32 ctl, reset_plm, engine, scratch, identity;
	if ((work->state != GU_PUBLISHED && work->state != GU_ACTIVE) || !work->master || !work->firmware_started)
		return GU_RESULT(-EINVAL);
	if (work->load->direct) {
		const struct gu_falcon_direct_image program = {
			.words = work->booter_cpu,
			.os_code_off = h->os_code_off, .os_code_size = h->os_code_size,
			.app_code_off = h->app_code_off, .app_code_size = h->app_code_size,
			.os_data_off = h->os_data_off, .os_data_size = h->os_data_size,
			.mailbox0 = lower_32_bits(work->meta_dma),
			.mailbox1 = upper_32_bits(work->meta_dma),
		};
		ret = gu_falcon_direct(&io, &sec2, &program, &work->launch);
	} else {
		const struct gu_falcon_hs_image program = {
			.dma = work->booter_dma,
			.code_off = h->app_code_off, .code_size = h->app_code_size,
			.code_va = h->app_code_off, .code_pa = 0,
			.data_off = h->os_data_off, .data_size = h->os_data_size, .data_pa = 0,
			.sig_dmem = h->patch_loc - h->os_data_off,
			.engine_mask = h->engine_id, .ucode_id = h->ucode_id,
			.mailbox0 = lower_32_bits(work->meta_dma),
			.mailbox1 = upper_32_bits(work->meta_dma),
		};
		ret = gu_falcon_hs(&io, &sec2, &program, &work->launch);
	}
	/* Always capture the first failure, including successful write/no halt. */
	if (diag_pci_dword(work, false, PCI_VENDOR_ID, &identity) ||
	    identity != pci_identity(work->pdev) ||
	    read_bar(work, GU_SEC2_BASE + GU_FALCON_CPUCTL_OFFSET, &ctl) || inaccessible(ctl) ||
	    read_bar(work, GU_SEC2_BASE + GU_FALCON_MAILBOX0_OFFSET, &work->mailbox0) ||
	    read_bar(work, GU_SEC2_BASE + GU_FALCON_MAILBOX1_OFFSET, &work->mailbox1) ||
	    read_bar(work, GU_SEC2_RESET_PLM_OFFSET, &reset_plm) ||
	    read_bar(work, GU_SEC2_BASE + GU_FALCON_ENGINE_OFFSET, &engine) || inaccessible(engine) ||
	    read_bar(work, GU_ACR_SCRATCH_OFFSET, &scratch))
		return GU_RESULT(-ENODEV);
	dev_dbg(&work->pdev->dev,
		 "completion diagnostics: engine=%#x acr_scratch@%#x=%#x secure_bus_owner=unavailable token_return=unobserved dmem_cleanup=unobserved\n",
		 engine, GU_ACR_SCRATCH_OFFSET, scratch);
	work->invocation_halted = !!(ctl & 16);
	work->fresh = work->launch.reset_asserted && work->launch.reset_released &&
		work->launch.reloaded && work->launch.started && work->invocation_halted;
	/* The reference exit does not write the mailboxes. Its nonzero input
	 * metadata pointer is therefore a reference-specific return, not the
	 * stock Booter zero-success convention. Hardware confirmation pending. */
	work->cleanup_complete = work->fresh && (reset_plm & 0xff) == 0xff &&
		work->mailbox0 == lower_32_bits(work->meta_dma) &&
		work->mailbox1 == upper_32_bits(work->meta_dma);
	dev_dbg(&work->pdev->dev,
		 "invocation: index=%zu attempt=%u reset=%u/%u reload=%u start=%u cpuctl=%#x reset_plm@%#x=%#x mailbox=%#x:%#x fresh=%u cleanup_observed=%u result=%d\n",
		 work->write_index, work->attempt, work->launch.reset_asserted,
		 work->launch.reset_released, work->launch.reloaded, work->launch.started, ctl,
		 GU_SEC2_RESET_PLM_OFFSET, reset_plm, work->mailbox1, work->mailbox0,
		 work->fresh, work->cleanup_complete, ret);
	if (ret || !work->cleanup_complete)
		dev_err(&work->pdev->dev,
			"invocation failed: index=%zu attempt=%u cpuctl=%#x engine=%#x reset_plm=%#x mailbox=%#x:%#x reset=%u/%u reload=%u start=%u fresh=%u cleanup=%u error=%d\n",
			work->write_index, work->attempt, ctl, engine, reset_plm,
			work->mailbox1, work->mailbox0, work->launch.reset_asserted,
			work->launch.reset_released, work->launch.reloaded, work->launch.started,
			work->fresh, work->cleanup_complete, ret ? ret : -EIO);
	return GU_RESULT(ret ? ret : work->cleanup_complete ? 0 : -EIO);
}

static void put_le64(u8 *dest, u64 value)
{
	unsigned int i;

	for (i = 0; i < 8; i++)
		dest[i] = (u8)(value >> (8 * i));
}

static int publish_signature(struct unlock_transaction_work *work)
{
	struct gpu_unlock_wpr_args args = {
		.fb_size = work->layout_in.usable_fb,
		.vga_offset = work->layout_in.vga_base,
		.frts_size = work->layout_in.frts_size,
		.signature_dma = work->payload_dma, .signature_size = GU_PAYLOAD_SIZE,
		.image_size = work->image_span.size,
		.boot_dma = work->boot_dma, .boot = work->boot_desc,
	};
	int ret;

	if (!work->meta_cpu || !work->stock_cpu || !work->pages_allocated ||
	    ((work->payload_dma | work->stock_dma | work->meta_dma) & 255) ||
	    work->state != GU_ALLOCATED)
		return GU_RESULT(-EINVAL);
	args.radix_dma = work->pages[0].dma;
	ret = gpu_unlock_wpr_meta_pack(work->meta_cpu, &work->layout, &args);
	if (ret)
		return GU_RESULT(ret);
	dma_wmb();
	work->state = GU_PUBLISHED;
	return 0;
}

static int restore_stock_signature(struct unlock_transaction_work *work)
{
	if (!work->meta_cpu || !work->stock_cpu ||
	    (work->state != GU_PUBLISHED && work->state != GU_ACTIVE))
		return GU_RESULT(-EINVAL);
	put_le64((u8 *)work->meta_cpu + 72, work->stock_dma);
	put_le64((u8 *)work->meta_cpu + 80, work->stock_size);
	dma_wmb();
	work->state = GU_STOCK;
	return 0;
}

static int restore_frts(struct unlock_transaction_work *work)
{
	u32 lo = 0, hi = 0;
	if (!work->frts_saved)
		return GU_RESULT(-EPROTO);
	read_bar(work, GU_WPR2_ADDR_LO_OFFSET, &lo);
	read_bar(work, GU_WPR2_ADDR_HI_OFFSET, &hi);
	dev_dbg(&work->pdev->dev, "WPR2 before restore: index=%zu attempt=%u lo=%#x hi=%#x\n",
		 work->write_index, work->attempt, lo, hi);
	write_bar(work, GU_WPR2_ADDR_LO_OFFSET, work->frts_lo);
	write_bar(work, GU_WPR2_ADDR_HI_OFFSET, work->frts_hi);
	if (read_bar(work, GU_WPR2_ADDR_LO_OFFSET, &lo) || read_bar(work, GU_WPR2_ADDR_HI_OFFSET, &hi))
		return GU_RESULT(-EIO);
	dev_dbg(&work->pdev->dev, "WPR2 restored: lo=%#x hi=%#x expected=%#x:%#x\n",
		 lo, hi, work->frts_lo, work->frts_hi);
	return GU_RESULT(lo == work->frts_lo && hi == work->frts_hi ? 0 : -EIO);
}
static int table_failure(struct unlock_transaction_work *work, const char *phase,
			 const struct gu_reg_write *entry, int ret)
{
	dev_err(&work->pdev->dev,
		"table failure: family=%s phase=%s index=%zu attempt=%u address=%#x expected=%#x observed=%#x error=%d\n",
		work->family->name, phase, work->write_index, work->attempt,
		entry->addr, entry->value, work->target_after, ret);
	return GU_RESULT(ret);
}
static int run_privileged_writes(struct unlock_transaction_work *work,
				 const struct gu_write_table *table)
{
	size_t i;
	int ret;
	if (work->state != GU_PUBLISHED && work->state != GU_ACTIVE)
		return GU_RESULT(-EPROTO);
	work->state = GU_ACTIVE;
	for (i = 0; i < table->count; i++) {
		const struct gu_reg_write *entry = &table->entries[i];
		work->write_index = i;
		for (work->attempt = 1; work->attempt <= 2; work->attempt++) {
			u32 lo = 0, hi = 0, ctl = 0, engine = 0;
			work->error_reported = false;
			work->fresh = work->cleanup_complete = false;
			memset(&work->launch, 0, sizeof(work->launch));
			work->target_after = 0;
			/* FWSEC completed before the first attempt. Every subsequent
			 * refill requires the prior invocation to have stopped. */
			if ((i || work->attempt > 1) && !work->invocation_halted)
				return table_failure(work, "prior-halt", entry, -EBUSY);
			ret = restore_frts(work);
			if (ret)
				return table_failure(work, "restore", entry, ret);
			if (read_bar(work, entry->addr, &work->target_before) ||
			    (work->target_before & 0xffff0000u) == 0xbadf0000u ||
			    read_bar(work, GU_SEC2_BASE + GU_FALCON_CPUCTL_OFFSET, &ctl) || inaccessible(ctl) ||
			    read_bar(work, GU_SEC2_BASE + GU_FALCON_ENGINE_OFFSET, &engine) || inaccessible(engine))
				return table_failure(work, "prelaunch", entry, -ENODEV);
			dev_dbg(&work->pdev->dev,
				 "prelaunch: index=%zu attempt=%u target=%#x cpuctl=%#x engine=%#x\n",
				 i, work->attempt, work->target_before, ctl, engine);
			gu_payload_fill(work->payload_cpu, entry->addr, entry->value);
			put_le64((u8 *)work->meta_cpu + 72, work->payload_dma);
			put_le64((u8 *)work->meta_cpu + 80, GU_PAYLOAD_SIZE);
			dma_wmb();
			dev_dbg(&work->pdev->dev,
				 "payload: reference=2d10f891 size=%#x dma=%#llx index=%zu attempt=%u address=%#x value=%#x\n",
				 GU_PAYLOAD_SIZE, (unsigned long long)work->payload_dma, i,
				 work->attempt, entry->addr, entry->value);
			ret = unlock_transaction_boot(work);
			if (read_bar(work, entry->addr, &work->target_after) ||
			    (work->target_after & 0xffff0000u) == 0xbadf0000u ||
			    read_bar(work, GU_WPR2_ADDR_LO_OFFSET, &lo) || read_bar(work, GU_WPR2_ADDR_HI_OFFSET, &hi))
				return table_failure(work, "result-inaccessible", entry, -ENODEV);
			dev_dbg(&work->pdev->dev,
				 "write result: index=%zu attempt=%u address=%#x expected=%#x observed=%#x wpr2=%#x:%#x write=%u fresh=%u cleanup_observed=%u\n",
				 i, work->attempt, entry->addr, entry->value,
				 work->target_after, lo, hi, work->target_after == entry->value,
				 work->fresh, work->cleanup_complete);
			if (ret) {
				dev_err(&work->pdev->dev, "failed invocation WPR2: actual=%#x:%#x saved_FRTS=%#x:%#x\n",
					lo, hi, work->frts_lo, work->frts_hi);
				return table_failure(work, "completion", entry, ret);
			}
			if (work->target_after == entry->value)
				break;
			/* Only literal idempotent PLMs belong here. A mismatching
			 * readback after proven halt/cleanup may be retried once.
			 * Errors/timeouts never replay an uncertain side effect. */
			table_failure(work, "readback", entry, -EIO);
		}
		if (work->target_after != entry->value)
			return table_failure(work, "readback-exhausted", entry, -EIO);
	}
	ret = restore_frts(work);
	return ret && table->count ?
		table_failure(work, "final-FRTS", &table->entries[table->count - 1], ret) : ret;
}

/* Write the unlock value to one speed selector and read it back. */
static int write_selector(struct unlock_transaction_work *work, const char *name,
			  u32 offset, u32 unlock)
{
	u32 value;

	if (read_bar(work, offset, &value) || inaccessible(value))
		return GU_RESULT(-ENODEV);
	dev_dbg(&work->pdev->dev, "selector read: %s=%#x expected_unlock=%#x\n",
		 name, value, unlock);
	dev_dbg(&work->pdev->dev, "selector write: %s=%#x\n", name, unlock);
	write_bar(work, offset, unlock);
	if (read_bar(work, offset, &value) || value == ~0u)
		return GU_RESULT(-ENODEV);
	return GU_RESULT(value == unlock ? 0 : -EIO);
}

static int run_host_writes(struct unlock_transaction_work *work,
			   const struct gu_write_table *table)
{
	size_t i;
	for (i = 0; i < table->count; i++) {
		const struct gu_reg_write *entry = &table->entries[i];
		int ret;
		work->write_index = i;
		ret = write_selector(work, "host", entry->addr, entry->value);
		if (ret) {
			read_bar(work, entry->addr, &work->target_after);
			return table_failure(work, "host", entry, ret);
		}
	}
	return 0;
}

/* PCI configuration can be ready before BAR0. The 610 BIF restore path waits
 * for PMC_BOOT_0 to match the saved chip ID before touching engine registers.
 * Transient badf/all-ones reads are expected only inside this bounded wait.
 */
static int wait_post_flr_bar(struct unlock_transaction_work *work, u32 chip)
{
	ktime_t deadline = ktime_add_us(ktime_get(), 1000000);
	u32 value = 0;

	for (;;) {
		if (read_bar(work, GU_PMC_BOOT_0_OFFSET, &value))
			return GU_RESULT(-EIO);
		if (value == chip) {
			dev_dbg(&work->pdev->dev, "post-FLR BAR ready: chip=%#x\n", value);
			return 0;
		}
		if (ktime_compare(ktime_get(), deadline) >= 0) {
			dev_err(&work->pdev->dev, "post-FLR BAR timeout: chip=%#x expected=%#x budget_us=1000000\n",
				value, chip);
			return GU_RESULT(-ETIMEDOUT);
		}
		usleep_range(1000, 2000);
	}
}

/* Match gpuWaitForGfwBootComplete_TU102, without launching any firmware or
 * overwriting the cold-entry evidence. The post-FLR ROM boot may still be busy.
 */
static int wait_post_flr_gfw(struct unlock_transaction_work *work)
{
	ktime_t deadline = ktime_add_us(ktime_get(), GU_GFW_TIMEOUT_US);
	struct gpu_unlock_gfw_sample sample = { };
	u32 identity = 0;
	int ret;

	for (;;) {
		sample = (struct gpu_unlock_gfw_sample){ };
		ret = diag_pci_dword(work, false, PCI_VENDOR_ID, &identity);
		sample.config_ok = !ret && identity == pci_identity(work->pdev);
		if (!sample.config_ok) {
			ret = -ENODEV;
			break;
		}
		if (read_bar(work, GU_GFW_CPUCTL_OFFSET, &sample.cpuctl) ||
		    read_bar(work, GU_GFW_PLM_OFFSET, &sample.plm)) {
			ret = -EIO;
			break;
		}
		/* Avoid the protected scratch read until PL0 can read it. */
		if (!inaccessible(sample.plm) && (sample.plm & GU_GFW_PLM_LEVEL0) &&
		    read_bar(work, GU_GFW_BOOT_OFFSET, &sample.boot)) {
			ret = -EIO;
			break;
		}
		ret = inaccessible(sample.plm) || inaccessible(sample.boot) ||
		      inaccessible(sample.cpuctl) ? -EAGAIN : gpu_unlock_gfw_assess(&sample);
		if (!ret)
			break;
		if (ktime_compare(ktime_get(), deadline) >= 0) {
			ret = -ETIMEDOUT;
			break;
		}
		usleep_range(1000, 2000);
	}
	dev_dbg(&work->pdev->dev, "post-FLR GFW result: error=%d pci=%#x plm=%#x boot=%#x cpuctl=%#x budget_us=%u\n",
		 ret, identity, sample.plm, sample.boot, sample.cpuctl, GU_GFW_TIMEOUT_US);
	return GU_RESULT(ret);
}

static int unlock_transaction_reset(struct unlock_transaction_work *work)
{
	u32 identity, bar, lo, hi, ss0, ss1, plm, chip, cpuctl;
	u16 command, pending;
	unsigned int i;
	int ret;

	if (work->state != GU_STOCK)
		return GU_RESULT(-EPROTO);
	if (read_bar(work, GU_FEAT_SS0_OFFSET, &ss0) || ss0 == ~0u ||
	    read_bar(work, GU_FEAT_SS1_OFFSET, &ss1) || ss1 == ~0u)
		return GU_RESULT(-ENODEV);
	dev_dbg(&work->pdev->dev, "pre-FLR selectors: ss0=%#x expected=%#x ss1=%#x expected=%#x\n",
		ss0, GU_SS0_UNLOCK, ss1, GU_SS1_UNLOCK);
	if (ss0 != GU_SS0_UNLOCK || ss1 != GU_SS1_UNLOCK)
		return GU_RESULT(-EIO);
	pci_clear_master(work->pdev);
	work->master = false;
	if (diag_pci_word(work, false, PCI_COMMAND, &command) ||
	    command == 0xffff || (command & PCI_COMMAND_MASTER))
		return GU_RESULT(-EIO);
	if (read_bar(work, GU_PMC_BOOT_0_OFFSET, &chip) || !chip || inaccessible(chip))
		return GU_RESULT(-ENODEV);
	/* Ampere PF-FLR requires no engine-reset preconditioning in this cold,
	 * unbound path (no initialized NVLink/P2P). The pinned GA102 rejoin14
	 * sequence also goes from the early PLM result to FLR. A pre-FLR engine
	 * hold is not a prerequisite: secure firmware can reject that write.
	 * Keep EVERY allocation alive, BME off, until post-FLR containment.
	 */
	/* FLR resets the display engine, so a firmware framebuffer (simpledrm,
	 * efifb) on this card must go first; nvidia-drm replaces it later. This
	 * does nothing on a card without one. After resume nvidia-drm already has.
	 */
	if (!work->resume) {
		ret = aperture_remove_conflicting_pci_devices(work->pdev, "gpu_unlock");
		if (ret)
			return GU_RESULT(ret);
	}
	dev_dbg(&work->pdev->dev, "PCIe FLR begin: BME=0 DMA retained, chip=%#x\n", chip);
	ret = pcie_flr(work->pdev);
	dev_dbg(&work->pdev->dev, "PCIe FLR returned: result=%d\n", ret);
	if (ret)
		return GU_RESULT(ret);
	/* The saved image predates BME. No transient restore with BME set. */
	pci_restore_state(work->pdev);
	if (diag_pci_dword(work, false, PCI_VENDOR_ID, &identity) ||
	    identity != pci_identity(work->pdev) ||
	    diag_pci_word(work, false, PCI_COMMAND, &command) ||
	    command == 0xffff || (command & PCI_COMMAND_MASTER) ||
	    !(command & PCI_COMMAND_MEMORY))
		return GU_RESULT(-ENODEV);
	for (i = 0; i < ARRAY_SIZE(work->bars); i++) {
		if (diag_pci_dword(work, false, PCI_BASE_ADDRESS_0 + i * 4, &bar) ||
		    bar != work->bars[i]) {
			dev_err(&work->pdev->dev, "post-FLR BAR%u: actual=%#x expected=%#x\n", i, bar, work->bars[i]);
			return GU_RESULT(-EIO);
		}
	}
	ret = wait_post_flr_bar(work, chip);
	if (ret)
		return GU_RESULT(ret);
	/* ROM GFW completion/halt plus FLR disposes of the old GSP execution.
	 * Stock RM checks this halt before resetting GSP with its own buffers.
	 */
	ret = wait_post_flr_gfw(work);
	if (ret)
		return GU_RESULT(ret);
	{
		struct gu_falcon_io io = falcon_io(work);
		struct gu_falcon_evidence reset;
		ret = gu_falcon_engine_reset(&io, GU_SEC2_BASE, "post-FLR", NULL, &reset);
	}
	if (ret)
		return GU_RESULT(ret);
	if (diag_pci_word(work, true, PCI_EXP_DEVSTA, &pending) ||
	    pending == 0xffff || (pending & PCI_EXP_DEVSTA_TRPND))
		return GU_RESULT(-EBUSY);
	if (read_bar(work, GU_GFW_CPUCTL_OFFSET, &cpuctl) || inaccessible(cpuctl) ||
	    !(cpuctl & GU_GFW_CPUCTL_HALTED) ||
	    read_bar(work, GU_WPR2_ADDR_LO_OFFSET, &lo) || inaccessible(lo) ||
	    read_bar(work, GU_WPR2_ADDR_HI_OFFSET, &hi) || inaccessible(hi) ||
	    read_bar(work, GU_FEAT_SS0_OFFSET, &ss0) || inaccessible(ss0) ||
	    read_bar(work, GU_FEAT_SS1_OFFSET, &ss1) || inaccessible(ss1) ||
	    read_bar(work, GU_FEAT_PLM_OFFSET, &plm) ||
	    (plm & 0xffff0000u) == 0xbadf0000u)
		return GU_RESULT(-ENODEV);
	dev_dbg(&work->pdev->dev,
		 "post-FLR SEC2 reset released, GSP halted, BME=0 pending=0 WPR2=%08x:%08x SS0=%08x SS1=%08x\n",
		 lo, hi, ss0, ss1);
	/* Both 610 and installed 615 _kgspBootGspRm reject preexisting WPR2
	 * on this cold dGPU path, even our old in-bounds FRTS reservation.
	 * kgspIsWpr2Up_TU102 uses HI.VAL != 0, not a LO/HI range comparison.
	 */
	if (hi >> 4) {
		dev_err(&work->pdev->dev, "post-FLR WPR2 remains enabled: lo=%#x hi=%#x; stock driver requires HI.VAL=0\n", lo, hi);
		return GU_RESULT(-EBUSY);
	}
	work->state = GU_QUIESCED;
	if (ss0 != GU_SS0_UNLOCK || ss1 != GU_SS1_UNLOCK)
		return GU_RESULT(-EIO);
	return 0;
}

int gpu_unlock_610_unlock(const struct gu_device *device, const struct gpu_unlock_610_shared *shared,
			  bool resume)
{
	struct pci_dev *pdev = device->pdev;
	struct unlock_transaction_work *work;
	const struct gpu_unlock_610_firmware *assets;
	int ret, cleanup;

	if (!device->recipe || !device->firmware)
		return -ENODEV;
	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return -ENOMEM;
	work->pdev = pci_dev_get(pdev);
	work->card = device->recipe;
	work->load = device->firmware;
	work->family = work->card->writes;
	assets = work->load->direct ? &shared->ga100 : &shared->ga10x;
	if (!assets->prepared || assets->error) {
		ret = assets->prepared ? assets->error : -EINVAL;
		pci_dev_put(work->pdev);
		kfree(work);
		return ret;
	}
	work->gsp_fw = assets->gsp;
	work->boot_fw = assets->boot;
	work->image_span = assets->image_span;
	work->sig_span = assets->sig_span;
	work->boot_desc = assets->boot_desc;
	work->radix = assets->radix;
	work->booter_fw = shared->booter;
	work->loader_fw = work->load->direct ? shared->loader : NULL;
	work->booter_hdr = shared->booter_hdr;
	work->booter_image_size = GU_BOOTER_IMAGE_SIZE;
	dev_dbg(&pdev->dev, "recipe selection: device=%#x family=%s privileged=%zu host=%zu direct=%u\n",
		 pdev->device, work->family->name, work->family->privileged.count,
		 work->family->host.count, work->load->direct);
	work->resume = resume;
	/* After resume GFW may still be running: check and wait before reading
	 * the layout. Firmware preparation has already completed for the round. */
	ret = resume ? unlock_transaction_suspended(work) : 0;
	if (!ret && !resume)
		ret = check_devres_empty(work, "entry");
	if (!ret)
		ret = unlock_transaction_claim(work);
	if (!ret) {
		u32 chip;
		if (read_bar(work, GU_PMC_BOOT_0_OFFSET, &chip) || inaccessible(chip) ||
		    ((chip >> 20) & 0x1ff) != work->card->chip)
			ret = GU_RESULT(-ENODEV);
	}
	if (!ret) {
		size_t i;
		for (i = 0; i < work->family->privileged.count; i++)
			if ((u64)work->family->privileged.entries[i].addr + 4 > work->bar_len)
				ret = GU_RESULT(-ERANGE);
	}
	if (!ret)
		ret = unlock_transaction_layout(work);
	if (!ret)
		ret = unlock_transaction_dma(work);
	if (!ret)
		ret = unlock_transaction_gfw(work);
	if (!ret)
		ret = unlock_transaction_fwsec(work);
	if (!ret)
		ret = publish_signature(work);
	if (!ret)
		ret = run_privileged_writes(work, &work->family->privileged);
	if (!ret)
		ret = restore_stock_signature(work);
	if (!ret)
		ret = run_host_writes(work, &work->family->host);
	if (!ret)
		ret = unlock_transaction_reset(work);
	/* Never leave the V67 signature published for a later stock boot. */
	if (ret && (work->state == GU_PUBLISHED || work->state == GU_ACTIVE))
		restore_stock_signature(work);
	work->error_reported = false;
	cleanup = unlock_transaction_unwind(work);
	if (!ret)
		ret = cleanup;
	if (work->retained) {
		/* Firmware may still DMA into these buffers: keep them, the device
		 * reference and this module until the next power off. */
		dev_err(&pdev->dev, "firmware did not stop; keeping its DMA buffers until power off\n");
		__module_get(THIS_MODULE);
		return ret;
	}
	pci_dev_put(work->pdev);
	kfree(work);
	return ret;
}

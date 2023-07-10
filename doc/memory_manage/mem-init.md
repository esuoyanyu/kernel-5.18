# 页表的建立
## idmap
> 创建恒等映射，把整个Image映射到虚拟地址空间，虚拟地址空间预留出FDT空间和SWAPPER_BLOCK空间。
> 在使能MMU后要使用虚拟地址空间，在使能MMU之前使用的物理地址空间，所以需要创建恒等映射来过渡。

[create_idmap](../../common/arch/arm64/kernel/head.S)
```
SYM_FUNC_START_LOCAL(create_idmap)
	mov	x28, lr
	/*
	 * The ID map carries a 1:1 mapping of the physical address range
	 * covered by the loaded image, which could be anywhere in DRAM. This
	 * means that the required size of the VA (== PA) space is decided at
	 * boot time, and could be more than the configured size of the VA
	 * space for ordinary kernel and user space mappings.
	 *
	 * There are three cases to consider here:
	 * - 39 <= VA_BITS < 48, and the ID map needs up to 48 VA bits to cover
	 *   the placement of the image. In this case, we configure one extra
	 *   level of translation on the fly for the ID map only. (This case
	 *   also covers 42-bit VA/52-bit PA on 64k pages).
	 *
	 * - VA_BITS == 48, and the ID map needs more than 48 VA bits. This can
	 *   only happen when using 64k pages, in which case we need to extend
	 *   the root level table rather than add a level. Note that we can
	 *   treat this case as 'always extended' as long as we take care not
	 *   to program an unsupported T0SZ value into the TCR register.
	 *
	 * - Combinations that would require two additional levels of
	 *   translation are not supported, e.g., VA_BITS==36 on 16k pages, or
	 *   VA_BITS==39/4k pages with 5-level paging, where the input address
	 *   requires more than 47 or 48 bits, respectively.
	 */
#if (VA_BITS < 48)
#define IDMAP_PGD_ORDER	(VA_BITS - PGDIR_SHIFT)
#define EXTRA_SHIFT	(PGDIR_SHIFT + PAGE_SHIFT - 3)

	/*
	 * If VA_BITS < 48, we have to configure an additional table level.
	 * First, we have to verify our assumption that the current value of
	 * VA_BITS was chosen such that all translation levels are fully
	 * utilised, and that lowering T0SZ will always result in an additional
	 * translation level to be configured.
	 */
#if VA_BITS != EXTRA_SHIFT
#error "Mismatch between VA_BITS and page size/number of translation levels"
#endif
#else
#define IDMAP_PGD_ORDER	(PHYS_MASK_SHIFT - PGDIR_SHIFT)
#define EXTRA_SHIFT
	/*
	 * If VA_BITS == 48, we don't have to configure an additional
	 * translation level, but the top-level table has more entries.
	 */
#endif
	adrp	x0, init_idmap_pg_dir
	adrp	x3, _text
	adrp	x6, _end + MAX_FDT_SIZE + SWAPPER_BLOCK_SIZE
	mov	x7, SWAPPER_RX_MMUFLAGS

	map_memory x0, x1, x3, x6, x7, x3, IDMAP_PGD_ORDER, x10, x11, x12, x13, x14, EXTRA_SHIFT

	/* Remap the kernel page tables r/w in the ID map */
	adrp	x1, _text
	adrp	x2, init_pg_dir
	adrp	x3, init_pg_end
	bic	x4, x2, #SWAPPER_BLOCK_SIZE - 1
	mov	x5, SWAPPER_RW_MMUFLAGS
	mov	x6, #SWAPPER_BLOCK_SHIFT
	bl	remap_region

	/* Remap the FDT after the kernel image */
	adrp	x1, _text
	adrp	x22, _end + SWAPPER_BLOCK_SIZE
	bic	x2, x22, #SWAPPER_BLOCK_SIZE - 1
	bfi	x22, x21, #0, #SWAPPER_BLOCK_SHIFT		// remapped FDT address
	add	x3, x2, #MAX_FDT_SIZE + SWAPPER_BLOCK_SIZE
	bic	x4, x21, #SWAPPER_BLOCK_SIZE - 1
	mov	x5, SWAPPER_RW_MMUFLAGS
	mov	x6, #SWAPPER_BLOCK_SHIFT
	bl	remap_region

	/*
	 * Since the page tables have been populated with non-cacheable
	 * accesses (MMU disabled), invalidate those tables again to
	 * remove any speculatively loaded cache lines.
	 */
	dmb	sy

	adrp	x0, init_idmap_pg_dir
	adrp	x1, init_idmap_pg_end
	bl	dcache_inval_poc
	ret	x28
SYM_FUNC_END(create_idmap)

# 创建页表的宏
/*
 * Map memory for specified virtual address range. Each level of page table needed supports
 * multiple entries. If a level requires n entries the next page table level is assumed to be
 * formed from n pages.
 *
 *	tbl:	location of page table
 *	rtbl:	address to be used for first level page table entry (typically tbl + PAGE_SIZE)
 *	vstart:	virtual address of start of range
 *	vend:	virtual address of end of range - we map [vstart, vend - 1]
 *	flags:	flags to use to map last level entries
 *	phys:	physical address corresponding to vstart - physical memory is contiguous
 *	order:  #imm 2log(number of entries in PGD table)
 *
 * If extra_shift is set, an extra level will be populated if the end address does
 * not fit in 'extra_shift' bits. This assumes vend is in the TTBR0 range.
 *
 * Temporaries:	istart, iend, tmp, count, sv - these need to be different registers
 * Preserves:	vstart, flags
 * Corrupts:	tbl, rtbl, vend, istart, iend, tmp, count, sv
 */
	.macro map_memory, tbl, rtbl, vstart, vend, flags, phys, order, istart, iend, tmp, count, sv, extra_shift
	sub \vend, \vend, #1
	add \rtbl, \tbl, #PAGE_SIZE
	mov \count, #0

	.ifnb	\extra_shift
	tst	\vend, #~((1 << (\extra_shift)) - 1)
	b.eq	.L_\@
	compute_indices \vstart, \vend, #\extra_shift, #(PAGE_SHIFT - 3), \istart, \iend, \count
	mov \sv, \rtbl
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
	.endif
.L_\@:
	compute_indices \vstart, \vend, #PGDIR_SHIFT, #\order, \istart, \iend, \count
	mov \sv, \rtbl
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv

#if SWAPPER_PGTABLE_LEVELS > 3
	compute_indices \vstart, \vend, #PUD_SHIFT, #(PAGE_SHIFT - 3), \istart, \iend, \count
	mov \sv, \rtbl
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
#endif

#if SWAPPER_PGTABLE_LEVELS > 2
	compute_indices \vstart, \vend, #SWAPPER_TABLE_SHIFT, #(PAGE_SHIFT - 3), \istart, \iend, \count
	mov \sv, \rtbl
	populate_entries \tbl, \rtbl, \istart, \iend, #PMD_TYPE_TABLE, #PAGE_SIZE, \tmp
	mov \tbl, \sv
#endif

	compute_indices \vstart, \vend, #SWAPPER_BLOCK_SHIFT, #(PAGE_SHIFT - 3), \istart, \iend, \count
	bic \rtbl, \phys, #SWAPPER_BLOCK_SIZE - 1
	populate_entries \tbl, \rtbl, \istart, \iend, \flags, #SWAPPER_BLOCK_SIZE, \tmp
	.endm

/*
 * Macro to populate page table entries, these entries can be pointers to the next level
 * or last level entries pointing to physical memory.
 *
 *	tbl:	page table address
 *	rtbl:	pointer to page table or physical memory
 *	index:	start index to write
 *	eindex:	end index to write - [index, eindex] written to
 *	flags:	flags for pagetable entry to or in
 *	inc:	increment to rtbl between each entry
 *	tmp1:	temporary variable
 *
 * Preserves:	tbl, eindex, flags, inc
 * Corrupts:	index, tmp1
 * Returns:	rtbl
 */
	.macro populate_entries, tbl, rtbl, index, eindex, flags, inc, tmp1
.Lpe\@:	phys_to_pte \tmp1, \rtbl
	orr	\tmp1, \tmp1, \flags	// tmp1 = table entry
	str	\tmp1, [\tbl, \index, lsl #3]
	add	\rtbl, \rtbl, \inc	// rtbl = pa next level
	add	\index, \index, #1
	cmp	\index, \eindex
	b.ls	.Lpe\@
	.endm

/*
 * Compute indices of table entries from virtual address range. If multiple entries
 * were needed in the previous page table level then the next page table level is assumed
 * to be composed of multiple pages. (This effectively scales the end index).
 *
 *	vstart:	virtual address of start of range
 *	vend:	virtual address of end of range - we map [vstart, vend]
 *	shift:	shift used to transform virtual address into index
 *	order:  #imm 2log(number of entries in page table)
 *	istart:	index in table corresponding to vstart
 *	iend:	index in table corresponding to vend
 *	count:	On entry: how many extra entries were required in previous level, scales
 *			  our end index.
 *		On exit: returns how many extra entries required for next page table level
 *
 * Preserves:	vstart, vend
 * Returns:	istart, iend, count
 */
	.macro compute_indices, vstart, vend, shift, order, istart, iend, count
	ubfx	\istart, \vstart, \shift, \order
	ubfx	\iend, \vend, \shift, \order
	add	\iend, \iend, \count, lsl \order
	sub	\count, \iend, \istart
	.endm

# 重新建立粗颗粒度的映射(2MB)
/*
 * Remap a subregion created with the map_memory macro with modified attributes
 * or output address. The entire remapped region must have been covered in the
 * invocation of map_memory.
 *
 * x0: last level table address (returned in first argument to map_memory)
 * x1: start VA of the existing mapping
 * x2: start VA of the region to update
 * x3: end VA of the region to update (exclusive)
 * x4: start PA associated with the region to update
 * x5: attributes to set on the updated region
 * x6: order of the last level mappings
 */
SYM_FUNC_START_LOCAL(remap_region)
	sub	x3, x3, #1		// make end inclusive

	// Get the index offset for the start of the last level table
	lsr	x1, x1, x6
	bfi	x1, xzr, #0, #PAGE_SHIFT - 3

	// Derive the start and end indexes into the last level table
	// associated with the provided region
	lsr	x2, x2, x6
	lsr	x3, x3, x6
	sub	x2, x2, x1
	sub	x3, x3, x1

	mov	x1, #1
	lsl	x6, x1, x6		// block size at this level

	populate_entries x0, x4, x2, x3, x5, x6, x7
	ret
SYM_FUNC_END(remap_region)

# 使能 mmu

/*
 * idmap_pg_dir是为turn on MMU准备的一致性映射，物理地址的高16bit都是0，因此identity mapping必定是选择
 * TTBR0_EL1指向的各级地址翻译表。后续当系统运行之后，在进程切换的时候，会修改TTBR0的值，切换到真实的进程
 * 地址空间上去。人为的把TTBR0_EL1用于USER SPACE全局页表项，TTBR1_EL1用于KERNEL SPACE全局页表项。
 */

/*
 * Enable the MMU.
 *
 *  x0  = SCTLR_EL1 value for turning on the MMU.
 *  x1  = TTBR1_EL1 value
 *  x2  = ID map root table address
 *
 * Returns to the caller via x30/lr. This requires the caller to be covered
 * by the .idmap.text section.
 *
 * Checks if the selected granule size is supported by the CPU.
 * If it isn't, park the CPU
 */
SYM_FUNC_START(__enable_mmu)
	mrs	x3, ID_AA64MMFR0_EL1
	ubfx	x3, x3, #ID_AA64MMFR0_EL1_TGRAN_SHIFT, 4
	cmp     x3, #ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MIN
	b.lt    __no_granule_support
	cmp     x3, #ID_AA64MMFR0_EL1_TGRAN_SUPPORTED_MAX
	b.gt    __no_granule_support
	phys_to_ttbr x2, x2
	msr	ttbr0_el1, x2			// load TTBR0
	load_ttbr1 x1, x1, x3

	set_sctlr_el1	x0

	ret
SYM_FUNC_END(__enable_mmu)
```

## 固定映射
> 固定映射的初始化，其作用是在系统启动过程中建立临时映射机制，目的时在建立真正的页表前完成对IO设备的访问，设备树的解析，以及在paging_init中的页表切换。

```
setup_arch->early_fixmap_init
          ->early_ioremap_init
          ->setup_machine_fdt
          ->paging_init
```

> [AArch64内存布局](../../common/Documentation/arm64/memory.rst)
```
setup_arch->early_fixmap_init

固定映射在AAech64 4KB页面 4级页表(48位地址宽度):
fffffbfff0000000	fffffbfffdffffff	 224MB		fixed mappings (top down)
```

> [建立映射框架，不关联具体页表项。](../../common/arch/arm64/mm/mmu.c)
```
static pte_t bm_pte[PTRS_PER_PTE] __page_aligned_bss;
static pmd_t bm_pmd[PTRS_PER_PMD] __page_aligned_bss __maybe_unused;
static pud_t bm_pud[PTRS_PER_PUD] __page_aligned_bss __maybe_unused;

/****FIX MAP虚拟地址空间****/

/*
 * The p*d_populate functions call virt_to_phys implicitly so they can't be used
 * directly on kernel symbols (bm_p*d). This function is called too early to use
 * lm_alias so __p*d_populate functions must be used to populate with the
 * physical address from __pa_symbol.
 */
void __init early_fixmap_init(void)
{
	pgd_t *pgdp;
	p4d_t *p4dp, p4d;
	pud_t *pudp;
	pmd_t *pmdp;
	unsigned long addr = FIXADDR_START;

	pgdp = pgd_offset_k(addr);
	p4dp = p4d_offset(pgdp, addr);
	p4d = READ_ONCE(*p4dp);
	if (CONFIG_PGTABLE_LEVELS > 3 &&
	    !(p4d_none(p4d) || p4d_page_paddr(p4d) == __pa_symbol(bm_pud))) {
		/*
		 * We only end up here if the kernel mapping and the fixmap
		 * share the top level pgd entry, which should only happen on
		 * 16k/4 levels configurations.
		 */
		BUG_ON(!IS_ENABLED(CONFIG_ARM64_16K_PAGES));
		pudp = pud_offset_kimg(p4dp, addr);
	} else {
		if (p4d_none(p4d))
			__p4d_populate(p4dp, __pa_symbol(bm_pud), P4D_TYPE_TABLE); //把bm_pud的物理地址写入到p4dp中
		pudp = fixmap_pud(addr);
	}
	if (pud_none(READ_ONCE(*pudp)))
		__pud_populate(pudp, __pa_symbol(bm_pmd), PUD_TYPE_TABLE); //把bm_pmd的物理地址写入到pudp中
	pmdp = fixmap_pmd(addr);
	__pmd_populate(pmdp, __pa_symbol(bm_pte), PMD_TYPE_TABLE); //把bm_pte的物理地址写入到pmdp中

	/*
	 * The boot-ioremap range spans multiple pmds, for which
	 * we are not prepared:
	 */
	BUILD_BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT)
		     != (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));

	if ((pmdp != fixmap_pmd(fix_to_virt(FIX_BTMAP_BEGIN)))
	     || pmdp != fixmap_pmd(fix_to_virt(FIX_BTMAP_END))) {
		WARN_ON(1);
		pr_warn("pmdp %p != %p, %p\n",
			pmdp, fixmap_pmd(fix_to_virt(FIX_BTMAP_BEGIN)),
			fixmap_pmd(fix_to_virt(FIX_BTMAP_END)));
		pr_warn("fix_to_virt(FIX_BTMAP_BEGIN): %08lx\n",
			fix_to_virt(FIX_BTMAP_BEGIN));
		pr_warn("fix_to_virt(FIX_BTMAP_END):   %08lx\n",
			fix_to_virt(FIX_BTMAP_END));

		pr_warn("FIX_BTMAP_END:       %d\n", FIX_BTMAP_END);
		pr_warn("FIX_BTMAP_BEGIN:     %d\n", FIX_BTMAP_BEGIN);
	}
}
```

> [固定映射的布局](../../common/arch/arm64/include/asm/fixmap.h)
```
/*
 * Here we define all the compile-time 'special' virtual
 * addresses. The point is to have a constant address at
 * compile time, but to set the physical address only
 * in the boot process.
 *
 * Each enum increment in these 'compile-time allocated'
 * memory buffers is page-sized. Use set_fixmap(idx,phys)
 * to associate physical memory with a fixmap index.
 */
enum fixed_addresses {
	FIX_HOLE,

	/*
	 * Reserve a virtual window for the FDT that is 2 MB larger than the
	 * maximum supported size, and put it at the top of the fixmap region.
	 * The additional space ensures that any FDT that does not exceed
	 * MAX_FDT_SIZE can be mapped regardless of whether it crosses any
	 * 2 MB alignment boundaries.
	 *
	 * Keep this at the top so it remains 2 MB aligned.
	 */
#define FIX_FDT_SIZE		(MAX_FDT_SIZE + SZ_2M)
	FIX_FDT_END,
	FIX_FDT = FIX_FDT_END + FIX_FDT_SIZE / PAGE_SIZE - 1,

	FIX_EARLYCON_MEM_BASE,
	FIX_TEXT_POKE0,

#ifdef CONFIG_ACPI_APEI_GHES
	/* Used for GHES mapping from assorted contexts */
	FIX_APEI_GHES_IRQ,
	FIX_APEI_GHES_SEA,
#ifdef CONFIG_ARM_SDE_INTERFACE
	FIX_APEI_GHES_SDEI_NORMAL,
	FIX_APEI_GHES_SDEI_CRITICAL,
#endif
#endif /* CONFIG_ACPI_APEI_GHES */

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
#ifdef CONFIG_RELOCATABLE
	FIX_ENTRY_TRAMP_TEXT4,	/* one extra slot for the data page */
#endif
	FIX_ENTRY_TRAMP_TEXT3,
	FIX_ENTRY_TRAMP_TEXT2,
	FIX_ENTRY_TRAMP_TEXT1,
#define TRAMP_VALIAS		(__fix_to_virt(FIX_ENTRY_TRAMP_TEXT1))
#endif /* CONFIG_UNMAP_KERNEL_AT_EL0 */
	__end_of_permanent_fixed_addresses,

	/*
	 * Temporary boot-time mappings, used by early_ioremap(),
	 * before ioremap() is functional.
	 */
#define NR_FIX_BTMAPS		(SZ_256K / PAGE_SIZE)
#define FIX_BTMAPS_SLOTS	7
#define TOTAL_FIX_BTMAPS	(NR_FIX_BTMAPS * FIX_BTMAPS_SLOTS)

	FIX_BTMAP_END = __end_of_permanent_fixed_addresses,
	FIX_BTMAP_BEGIN = FIX_BTMAP_END + TOTAL_FIX_BTMAPS - 1,

	/*
	 * Used for kernel page table creation, so unmapped memory may be used
	 * for tables.
	 */
	FIX_PTE,
	FIX_PMD,
	FIX_PUD,
	FIX_PGD,

	__end_of_fixed_addresses
};
```

### fix map在early ioremap中的使用
> [创建ioremap，给启动早期的外设使用](../../common/mm/early_ioremap.c)
> 使用已经规划好的分区，将虚拟地址填入到slot_virt中
```
static unsigned long slot_virt[FIX_BTMAPS_SLOTS] __initdata;

void __init early_ioremap_setup(void)
{
	int i;

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		if (WARN_ON(prev_map[i]))
			break;

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		slot_virt[i] = __fix_to_virt(FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*i);
}
```

> [使用ioremap，在系统启动早期，给外设的物理地址建立虚拟映射](../../common/mm/early_ioremap.c)
> 把外设的物理地址填充到FIXMAP_PAGE_IO区域的PTE(页表项)中。
```
static void __init __iomem *
__early_ioremap(resource_size_t phys_addr, unsigned long size, pgprot_t prot)
{
	unsigned long offset;
	resource_size_t last_addr;
	unsigned int nrpages;
	enum fixed_addresses idx;
	int i, slot;

	WARN_ON(system_state >= SYSTEM_RUNNING);

	slot = -1;
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++) {
		if (!prev_map[i]) {
			slot = i;
			break;
		}
	}

	if (WARN(slot < 0, "%s(%pa, %08lx) not found slot\n",
		 __func__, &phys_addr, size))
		return NULL;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (WARN_ON(!size || last_addr < phys_addr))
		return NULL;

	prev_size[slot] = size;
	/*
	 * Mappings have to be page-aligned
	 */
	offset = offset_in_page(phys_addr);
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr + 1) - phys_addr;

	/*
	 * Mappings have to fit in the FIX_BTMAP area.
	 */
	nrpages = size >> PAGE_SHIFT;
	if (WARN_ON(nrpages > NR_FIX_BTMAPS))
		return NULL;

	/*
	 * Ok, go for it..
	 */
	idx = FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*slot;
	while (nrpages > 0) {
		if (after_paging_init)
			__late_set_fixmap(idx, phys_addr, prot);
		else
			__early_set_fixmap(idx, phys_addr, prot);
		phys_addr += PAGE_SIZE;
		--idx;
		--nrpages;
	}
	WARN(early_ioremap_debug, "%s(%pa, %08lx) [%d] => %08lx + %08lx\n",
	     __func__, &phys_addr, size, slot, offset, slot_virt[slot]);

	prev_map[slot] = (void __iomem *)(offset + slot_virt[slot]);
	return prev_map[slot];
}
```

### fix map在early console中的使用
> 使用FIX_EARLYCON_MEM_BASE区域创建物理地址到虚拟地址的映射，即填充物理地址的页帧号到PTE。
> [创建物理地址到虚拟地址的映射](../../common/drivers/tty/serial/earlycon.c)
```
static void __iomem * __init earlycon_map(resource_size_t paddr, size_t size)
{
	void __iomem *base;
#ifdef CONFIG_FIX_EARLYCON_MEM
	set_fixmap_io(FIX_EARLYCON_MEM_BASE, paddr & PAGE_MASK);
	base = (void __iomem *)__fix_to_virt(FIX_EARLYCON_MEM_BASE);
	base += paddr & ~PAGE_MASK;
#else
	base = ioremap(paddr, size);
#endif
	if (!base)
		pr_err("%s: Couldn't map %pa\n", __func__, &paddr);

	return base;
}
```

> 把物理地址的页帧号填充到FIX_EARLYCON_MEM_BASE区域的页表项。
> [设置物理地址到虚拟地址的映射](../../common/arch/arm64/mm/mmu.c)
```
#define set_fixmap_io(idx, phys) \
	__set_fixmap(idx, phys, FIXMAP_PAGE_IO)

/*
 * To avoid TLB flush broadcasts, this uses local_flush_tlb_kernel_range().
 * As a result, this can only be called with preemption disabled, as under
 * stop_machine().
 */
void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
	unsigned long vaddr = __fix_to_virt(idx);
	pte_t *pte = pte_offset_fixmap(pmd_off_k(vaddr), vaddr);

	/* Make sure fixmap region does not exceed available allocation. */
	BUILD_BUG_ON(__fix_to_virt(__end_of_fixed_addresses) < FIXADDR_START);
	BUG_ON(idx >= __end_of_fixed_addresses);

	/* We support only device mappings before pgprot_kernel is set. */
	if (WARN_ON(pgprot_val(prot) != pgprot_val(FIXMAP_PAGE_IO) &&
		    pgprot_val(prot) && pgprot_val(pgprot_kernel) == 0))
		return;

	if (pgprot_val(prot))
		set_pte_at(NULL, vaddr, pte,
			pfn_pte(phys >> PAGE_SHIFT, prot));
	else
		pte_clear(NULL, vaddr, pte);
	local_flush_tlb_kernel_range(vaddr, vaddr + PAGE_SIZE);
}
```

### fix map在device-tree中的使用
> 建立设备树物理地址到虚拟地址的映射并解析设备树。
> [建立映射并解析设备树](../../common/arch/arm64/kernel/setup.c)
```
static void __init setup_machine_fdt(phys_addr_t dt_phys)
{
	int size;
	void *dt_virt = fixmap_remap_fdt(dt_phys, &size, PAGE_KERNEL);
	const char *name;

	if (dt_virt)
		memblock_reserve(dt_phys, size);

	if (!dt_virt || !early_init_dt_scan(dt_virt)) {
		pr_crit("\n"
			"Error: invalid device tree blob at physical address %pa (virtual address 0x%px)\n"
			"The dtb must be 8-byte aligned and must not exceed 2 MB in size\n"
			"\nPlease check your bootloader.",
			&dt_phys, dt_virt);

		/*
		 * Note that in this _really_ early stage we cannot even BUG()
		 * or oops, so the least terrible thing to do is cpu_relax(),
		 * or else we could end-up printing non-initialized data, etc.
		 */
		while (true)
			cpu_relax();
	}

	/* Early fixups are done, map the FDT as read-only now */
	fixmap_remap_fdt(dt_phys, &size, PAGE_KERNEL_RO);

	name = of_flat_dt_get_machine_name();
	if (!name)
		return;

	pr_info("Machine model: %s\n", name);
	dump_stack_set_arch_desc("%s (DT)", name);
}
````

> 使用FIX_FDT,设备树物理地址到虚拟地址的映射，最大建立2MB的block entry.
> [建立物理地址到虚拟地址的映射](../../common/arch/arm64/mm/mmu.c)
```
void *__init fixmap_remap_fdt(phys_addr_t dt_phys, int *size, pgprot_t prot)
{
	const u64 dt_virt_base = __fix_to_virt(FIX_FDT);
	int offset;
	void *dt_virt;

	/*
	 * Check whether the physical FDT address is set and meets the minimum
	 * alignment requirement. Since we are relying on MIN_FDT_ALIGN to be
	 * at least 8 bytes so that we can always access the magic and size
	 * fields of the FDT header after mapping the first chunk, double check
	 * here if that is indeed the case.
	 */
	BUILD_BUG_ON(MIN_FDT_ALIGN < 8);
	if (!dt_phys || dt_phys % MIN_FDT_ALIGN)
		return NULL;

	/*
	 * Make sure that the FDT region can be mapped without the need to
	 * allocate additional translation table pages, so that it is safe
	 * to call create_mapping_noalloc() this early.
	 *
	 * On 64k pages, the FDT will be mapped using PTEs, so we need to
	 * be in the same PMD as the rest of the fixmap.
	 * On 4k pages, we'll use section mappings for the FDT so we only
	 * have to be in the same PUD.
	 */
	BUILD_BUG_ON(dt_virt_base % SZ_2M);

	BUILD_BUG_ON(__fix_to_virt(FIX_FDT_END) >> SWAPPER_TABLE_SHIFT !=
		     __fix_to_virt(FIX_BTMAP_BEGIN) >> SWAPPER_TABLE_SHIFT);

	offset = dt_phys % SWAPPER_BLOCK_SIZE;
	dt_virt = (void *)dt_virt_base + offset;

	/* map the first chunk so we can read the size from the header */
	create_mapping_noalloc(round_down(dt_phys, SWAPPER_BLOCK_SIZE),
			dt_virt_base, SWAPPER_BLOCK_SIZE, prot);

	if (fdt_magic(dt_virt) != FDT_MAGIC)
		return NULL;

	*size = fdt_totalsize(dt_virt);
	if (*size > MAX_FDT_SIZE)
		return NULL;

	if (offset + *size > SWAPPER_BLOCK_SIZE)
		create_mapping_noalloc(round_down(dt_phys, SWAPPER_BLOCK_SIZE), dt_virt_base,
			       round_up(offset + *size, SWAPPER_BLOCK_SIZE), prot);

	return dt_virt;
}
```

### fix map在建立内核全局页表项中的使用
> 借助fix map建立内核空间的全局页表
> [建立内核空间全局页表](../../common/arch/arm64/mm/mmu.c)
```
void __init paging_init(void)
{
	pgd_t *pgdp = pgd_set_fixmap(__pa_symbol(swapper_pg_dir));
	extern pgd_t init_idmap_pg_dir[];

	idmap_t0sz = 63UL - __fls(__pa_symbol(_end) | GENMASK(VA_BITS_MIN - 1, 0));

	map_kernel(pgdp);
	map_mem(pgdp);

	pgd_clear_fixmap();

	cpu_replace_ttbr1(lm_alias(swapper_pg_dir), init_idmap_pg_dir);
	init_mm.pgd = swapper_pg_dir;

	memblock_phys_free(__pa_symbol(init_pg_dir),
			   __pa_symbol(init_pg_end) - __pa_symbol(init_pg_dir));

	memblock_allow_resize();

	create_idmap();
}
```

## 内核全局页表swapper_pg_dir
> paging_init，建立内核全局页表，重新设置ttbr1寄存器。释放init_pg_dir内存。以后内核空间使用内核全局页表，线性地址空间与物理地址空间的转换，VA-线性地址空间起始地址+物理内存空间起始地址。vmallc的虚拟地址，借助页表把不连续的物理地址映射到连续的虚拟地址空间(vmalloc地址空间)，所以可能会产生缺页异常。


# 内存管理初始化
## memblock
> 早期内存管理使用memblock/bootmem分配器，ARM64已经不使用bootmem分配器，而是使用memblock分配器。
> memblock_add，添加内存区域。
> [memblock_add](../../common/mm/memblock.c)
```
/**
 * memblock_add - add new memblock region
 * @base: base address of the new region
 * @size: size of the new region
 *
 * Add new memblock region [@base, @base + @size) to the "memory"
 * type. See memblock_add_range() description for mode details
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_add(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_add_range(&memblock.memory, base, size, MAX_NUMNODES, 0);
}
```

> memblock_remove，删除内存区域。
> [memblock_remove](../../common/mm/memblock.c)
```
int __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_remove_range(&memblock.memory, base, size);
}
```

> memblock_alloc，分配内存。
> [memblock_alloc](../../common/mm/memblock.c)
```
int __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_remove_range(&memblock.memory, base, size);
}

/**
 * memblock_alloc_try_nid - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. This function zeroes the allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void * __init memblock_alloc_try_nid(
			phys_addr_t size, phys_addr_t align,
			phys_addr_t min_addr, phys_addr_t max_addr,
			int nid)
{
	void *ptr;

	memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
		     __func__, (u64)size, (u64)align, nid, &min_addr,
		     &max_addr, (void *)_RET_IP_);
	ptr = memblock_alloc_internal(size, align,
					   min_addr, max_addr, nid, false);
	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}
```

## 调整物理内存
> 解析完设备树，把物理内存都添加都系统后，对物理内存进行调整。主要是把特殊的区域添加到memblock的reversed中，如dts中的reversed内存区域，申请的CAMA区域。
> [调整添加到系统的内存区域](../../common/arch/arm64/mm/init.c)
```
void __init arm64_memblock_init(void)
{
	s64 linear_region_size = PAGE_END - _PAGE_OFFSET(vabits_actual);

	/*
	 * Corner case: 52-bit VA capable systems running KVM in nVHE mode may
	 * be limited in their ability to support a linear map that exceeds 51
	 * bits of VA space, depending on the placement of the ID map. Given
	 * that the placement of the ID map may be randomized, let's simply
	 * limit the kernel's linear map to 51 bits as well if we detect this
	 * configuration.
	 */
	if (IS_ENABLED(CONFIG_KVM) && vabits_actual == 52 &&
	    is_hyp_mode_available() && !is_kernel_in_hyp_mode()) {
		pr_info("Capping linear region to 51 bits for KVM in nVHE mode on LVA capable hardware.\n");
		linear_region_size = min_t(u64, linear_region_size, BIT(51));
	}

	/* Remove memory above our supported physical address size */
	memblock_remove(1ULL << PHYS_MASK_SHIFT, ULLONG_MAX);

	/*
	 * Select a suitable value for the base of physical memory.
	 */
	memstart_addr = round_down(memblock_start_of_DRAM(),
				   ARM64_MEMSTART_ALIGN);

	if ((memblock_end_of_DRAM() - memstart_addr) > linear_region_size)
		pr_warn("Memory doesn't fit in the linear mapping, VA_BITS too small\n");

	/*
	 * Remove the memory that we will not be able to cover with the
	 * linear mapping. Take care not to clip the kernel which may be
	 * high in memory.
	 */
	memblock_remove(max_t(u64, memstart_addr + linear_region_size,
			__pa_symbol(_end)), ULLONG_MAX);
	if (memstart_addr + linear_region_size < memblock_end_of_DRAM()) {
		/* ensure that memstart_addr remains sufficiently aligned */
		memstart_addr = round_up(memblock_end_of_DRAM() - linear_region_size,
					 ARM64_MEMSTART_ALIGN);
		memblock_remove(0, memstart_addr);
	}

	/*
	 * If we are running with a 52-bit kernel VA config on a system that
	 * does not support it, we have to place the available physical
	 * memory in the 48-bit addressable part of the linear region, i.e.,
	 * we have to move it upward. Since memstart_addr represents the
	 * physical address of PAGE_OFFSET, we have to *subtract* from it.
	 */
	if (IS_ENABLED(CONFIG_ARM64_VA_BITS_52) && (vabits_actual != 52))
		memstart_addr -= _PAGE_OFFSET(48) - _PAGE_OFFSET(52);

	/*
	 * Apply the memory limit if it was set. Since the kernel may be loaded
	 * high up in memory, add back the kernel region that must be accessible
	 * via the linear mapping.
	 */
	if (memory_limit != PHYS_ADDR_MAX) {
		memblock_mem_limit_remove_map(memory_limit);
		memblock_add(__pa_symbol(_text), (u64)(_end - _text));
	}

	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/*
		 * Add back the memory we just removed if it results in the
		 * initrd to become inaccessible via the linear mapping.
		 * Otherwise, this is a no-op
		 */
		u64 base = phys_initrd_start & PAGE_MASK;
		u64 size = PAGE_ALIGN(phys_initrd_start + phys_initrd_size) - base;

		/*
		 * We can only add back the initrd memory if we don't end up
		 * with more memory than we can address via the linear mapping.
		 * It is up to the bootloader to position the kernel and the
		 * initrd reasonably close to each other (i.e., within 32 GB of
		 * each other) so that all granule/#levels combinations can
		 * always access both.
		 */
		if (WARN(base < memblock_start_of_DRAM() ||
			 base + size > memblock_start_of_DRAM() +
				       linear_region_size,
			"initrd not fully accessible via the linear mapping -- please check your bootloader ...\n")) {
			phys_initrd_size = 0;
		} else {
			memblock_add(base, size);
			memblock_clear_nomap(base, size);
			memblock_reserve(base, size);
		}
	}

	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		extern u16 memstart_offset_seed;
		u64 mmfr0 = read_cpuid(ID_AA64MMFR0_EL1);
		int parange = cpuid_feature_extract_unsigned_field(
					mmfr0, ID_AA64MMFR0_EL1_PARANGE_SHIFT);
		s64 range = linear_region_size -
			    BIT(id_aa64mmfr0_parange_to_phys_shift(parange));

		/*
		 * If the size of the linear region exceeds, by a sufficient
		 * margin, the size of the region that the physical memory can
		 * span, randomize the linear region as well.
		 */
		if (memstart_offset_seed > 0 && range >= (s64)ARM64_MEMSTART_ALIGN) {
			range /= ARM64_MEMSTART_ALIGN;
			memstart_addr -= ARM64_MEMSTART_ALIGN *
					 ((range * memstart_offset_seed) >> 16);
		}
	}

	/*
	 * Register the kernel text, kernel data, initrd, and initial
	 * pagetables with memblock.
	 */
	memblock_reserve(__pa_symbol(_stext), _end - _stext);
	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/* the generic initrd code expects virtual addresses */
		initrd_start = __phys_to_virt(phys_initrd_start);
		initrd_end = initrd_start + phys_initrd_size;
	}

	early_init_fdt_scan_reserved_mem();

	if (!defer_reserve_crashkernel())
		reserve_crashkernel();

	high_memory = __va(memblock_end_of_DRAM() - 1) + 1;
}

```

## 内存初始化
```
mm_init->mem_init 初始化伙伴系统
       ->kmem_cache_init slb初始化
       ->vmalloc_init vmalloc初始化
```
> 至此，系统内存管理初始化完成，伙伴系统内存管理器接管系统内存管理。

# 总体流程
```
start_kernel->setup_arch->early_fixmap_init #初始化固定映射
                        ->early_ioremap_init #初始化内存映射区，为早期访问外设内存做准备。
                        ->setup_machine_fdt  #映射fdt并解析设备树。
                        ->arm64_memblock_init #调整添加的物理内存
                        ->paging_init #建立内核空间的页表
                        ->bootmem_init #初始化早期内存管理器memblock
            ->page_alloc_init #
            ->mm_init->mem_init #初始化伙伴系统
                    ->kmem_cache_init #初始化slab分配器
                    ->vmalloc_init #初始化vmalloc分配机制
```



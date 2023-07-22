# 伙伴系统
> 伙伴系统是linux经典的物理内存管理系统，用来分配和释放连续的物理内存，可以减少内存分配和释放过程产生的外部碎片问题。伙伴系统按阶为单位分配内存块，范围为0-MAX_ORDER, MAX_ORDER经典值是11，对于4KB页面，一次最大分配是8MB。

> 伙伴系统算法的简单描述: 
> 1. 内存块被划分为一系列大小相等的内存页框。每个内存页框的大小是2的幂次方，例如4KB、8KB、16KB等。
> 2. 内存块按照大小被组织成一个二叉树的结构，其中根节点代表整个可用内存区域。树的每个节点表示一个内存块，每个节点的大小是其子节点的大小之和。
> 3. 当进程请求分配一定大小的内存时，伙伴系统算法会在树中找到合适大小的空闲内存块。如果找到的内存块比所需的内存稍大，可以将其分割成两个较小的内存块，并继续在子树中查找可用的内存块。
> 4. 如果没有找到足够大的空闲内存块，算法会向上遍历树，寻找较大的内存块进行分割，直到找到合适的内存块或者到达根节点。
> 5. 当进程释放一块内存时，算法会将该内存块与其伙伴合并，形成一个较大的内存块。合并后的内存块会被重新加入到可用内存池中。
> 
> 通过这种方式，伙伴系统算法在分配和释放内存时尽量保持内存的连续性，减少内存碎片化的发生。它通过树状结构的组织和内存块的合并操作，提供了一种高效的内存管理方式。
> 需要注意的是，伙伴系统算法也存在一些缺点，例如内存浪费和外部碎片化的问题。为了解决这些问题，还可以结合其他的内存分配算法和技术，如slab分配器和内存压缩等。

## MAX_ORDER
```
xxx
```

## 伙伴系统的核心
> 一般情况走快速分配路径。
> 在系统内存不足时走慢速路径，会进行页面同步和回收。
> [伙伴系统的核心](../../common/mm/page_alloc.c)
```
/*
 * This is the 'heart' of the zoned buddy allocator.
 */
struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
							nodemask_t *nodemask)
{
	struct page *page;
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	gfp_t alloc_gfp; /* The gfp_t that was actually used for allocation */
	struct alloc_context ac = { };

	/*
	 * There are several places where we assume that the order value is sane
	 * so bail out early if the request is out of bound.
	 */
	if (unlikely(order >= MAX_ORDER)) {
		WARN_ON_ONCE(!(gfp & __GFP_NOWARN));
		return NULL;
	}

	gfp &= gfp_allowed_mask;
	/*
	 * Apply scoped allocation constraints. This is mainly about GFP_NOFS
	 * resp. GFP_NOIO which has to be inherited for all allocation requests
	 * from a particular context which has been marked by
	 * memalloc_no{fs,io}_{save,restore}. And PF_MEMALLOC_PIN which ensures
	 * movable zones are not used during allocation.
	 */
	gfp = current_gfp_context(gfp);
	alloc_gfp = gfp;
	if (!prepare_alloc_pages(gfp, order, preferred_nid, nodemask, &ac,
			&alloc_gfp, &alloc_flags))
		return NULL;

	/*
	 * Forbid the first pass from falling back to types that fragment
	 * memory until all local zones are considered.
	 */
	alloc_flags |= alloc_flags_nofragment(ac.preferred_zoneref->zone, gfp);

	/* First allocation attempt */
	page = get_page_from_freelist(alloc_gfp, order, alloc_flags, &ac);
	if (likely(page))
		goto out;

	alloc_gfp = gfp;
	ac.spread_dirty_pages = false;

	/*
	 * Restore the original nodemask if it was potentially replaced with
	 * &cpuset_current_mems_allowed to optimize the fast-path attempt.
	 */
	ac.nodemask = nodemask;

	page = __alloc_pages_slowpath(alloc_gfp, order, &ac);

out:
	if (memcg_kmem_enabled() && (gfp & __GFP_ACCOUNT) && page &&
	    unlikely(__memcg_kmem_charge_page(page, gfp, order) != 0)) {
		__free_pages(page, order);
		page = NULL;
	}

	trace_mm_page_alloc(page, order, alloc_gfp, ac.migratetype);

	return page;
}
EXPORT_SYMBOL(__alloc_pages);
```



// SPDX-License-Identifier: GPL-2.0-only
/*
 * cppc.c: CPPC Interface for x86
 * Copyright (c) 2016, Intel Corporation.
 */

#include <acpi/cppc_acpi.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/topology.h>

/* Refer to drivers/acpi/cppc_acpi.c for the description of functions */

bool cpc_supported_by_cpu(void)
{
	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		return boot_cpu_has(X86_FEATURE_CPPC);
	}
	return false;
}

bool cpc_ffh_supported(void)
{
	return true;
}

int cpc_read_ffh(int cpunum, struct cpc_reg *reg, u64 *val)
{
	int err;

	err = rdmsrl_safe_on_cpu(cpunum, reg->address, val);
	if (!err) {
		u64 mask = GENMASK_ULL(reg->bit_offset + reg->bit_width - 1,
				       reg->bit_offset);

		*val &= mask;
		*val >>= reg->bit_offset;
	}
	return err;
}

int cpc_write_ffh(int cpunum, struct cpc_reg *reg, u64 val)
{
	u64 rd_val;
	int err;

	err = rdmsrl_safe_on_cpu(cpunum, reg->address, &rd_val);
	if (!err) {
		u64 mask = GENMASK_ULL(reg->bit_offset + reg->bit_width - 1,
				       reg->bit_offset);

		val <<= reg->bit_offset;
		val &= mask;
		rd_val &= ~mask;
		rd_val |= val;
		err = wrmsrl_safe_on_cpu(cpunum, reg->address, rd_val);
	}
	return err;
}

bool amd_set_max_freq_ratio(u64 *ratio)
{
	struct cppc_perf_caps perf_caps;
	u64 highest_perf, nominal_perf;
	u64 perf_ratio;
	int rc;

	if (!ratio)
		return false;

	rc = cppc_get_perf_caps(0, &perf_caps);
	if (rc) {
		pr_debug("Could not retrieve perf counters (%d)\n", rc);
		return false;
	}

	highest_perf = amd_get_highest_perf();
	nominal_perf = perf_caps.nominal_perf;

	if (!highest_perf || !nominal_perf) {
		pr_debug("Could not retrieve highest or nominal performance\n");
		return false;
	}

	perf_ratio = div_u64(highest_perf * SCHED_CAPACITY_SCALE, nominal_perf);
	/* midpoint between max_boost and max_P */
	perf_ratio = (perf_ratio + SCHED_CAPACITY_SCALE) >> 1;
	if (!perf_ratio) {
		pr_debug("Non-zero highest/nominal perf values led to a 0 ratio\n");
		return false;
	}

	*ratio = perf_ratio;
	arch_set_max_freq_ratio(false);

	return true;
}

static DEFINE_MUTEX(freq_invariance_lock);

void init_freq_invariance_cppc(void)
{
	static bool secondary;

	mutex_lock(&freq_invariance_lock);

	init_freq_invariance(secondary, true);
	secondary = true;

	mutex_unlock(&freq_invariance_lock);
}

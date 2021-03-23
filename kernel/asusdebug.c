/* //20100930 jack_wong for asus debug mechanisms +++++
 *  asusdebug.c
 * //20100930 jack_wong for asus debug mechanisms -----
 *
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/rtc.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched/clock.h>
#include <linux/sched.h>
#include <soc/qcom/minidump.h>

extern int g_user_dbg_mode;

#include <linux/rtc.h>
#include "locking/rtmutex_common.h"

#include <linux/input/qpnp-power-on.h>

extern char evtlog_bootup_reason[50];

#ifdef CONFIG_HAS_EARLYSUSPEND
int entering_suspend = 0;
#endif

phys_addr_t PRINTK_BUFFER_PA = 0x97000000;
void *PRINTK_BUFFER_VA;
phys_addr_t RTB_BUFFER_PA = 0x97000000 + SZ_2M;
ulong logcat_buffer_index = 0;

//#define RT_MUTEX_HAS_WAITERS    1UL
//#define RT_MUTEX_OWNER_MASKALL  1UL
struct mutex fake_mutex;
struct completion fake_completion;
struct rt_mutex fake_rtmutex;

/*
 * rtc read time
 */
extern struct timezone sys_tz;
int asus_rtc_read_time(struct rtc_time *tm)
{
	struct timespec ts;

	getnstimeofday(&ts);
	ts.tv_sec -= sys_tz.tz_minuteswest * 60;
	rtc_time_to_tm(ts.tv_sec, tm);
	printk("now %04d%02d%02d-%02d%02d%02d, tz=%d\r\n", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, sys_tz.tz_minuteswest);
	return 0;
}
EXPORT_SYMBOL(asus_rtc_read_time);

/*
 * memset for non cached memory
 */
void *memset_nc(void *s, int c, size_t count)
{
	volatile u8 *p = s;

	while (count--)
		*p++ = c;
	return s;
}
EXPORT_SYMBOL(memset_nc);

/*
 *memcpy for non cached memory
 */
void *memcpy_nc(void *dest, const void *src, size_t n)
{
	int i = 0;
	u8 *d = (u8 *)dest, *s = (u8 *)src;
	for (i = 0; i < n; i++)
		d[i] = s[i];

	return dest;
}
EXPORT_SYMBOL(memcpy_nc);

static char *g_phonehang_log;
static int g_iPtr = 0;
int save_log(const char *f, ...)
{
	char buf[1024];
	va_list args;
	int len;

	if (g_iPtr < PHONE_HANG_LOG_SIZE) {
		va_start(args, f);
		len = vsnprintf(buf, sizeof(buf), f, args);
		va_end(args);

		if ((g_iPtr + len) < PHONE_HANG_LOG_SIZE) {
			memcpy_nc((char*)g_phonehang_log + g_iPtr, (char*)buf, len);
			g_iPtr += len;
			return 0;
		}
	}
	printk("slowlog over size\n");
	g_iPtr = PHONE_HANG_LOG_SIZE;
	return -1;
}

struct thread_info_save;
struct thread_info_save {
	struct task_struct *		pts;
	pid_t				pid;
	u64				sum_exec_runtime;
	u64				vruntime;
	struct thread_info_save *	pnext;
};

#define MAX_STACK_TRACE_DEPTH   64
struct stack_trace_data {
	struct stack_trace *	trace;
	unsigned int		no_sched_functions;
	unsigned int		skip;
};

struct stackframe {
	unsigned long	fp;
	unsigned long	sp;
	unsigned long	lr;
	unsigned long	pc;
};
int unwind_frame(struct stackframe *frame);
void notrace walk_stackframe(struct stackframe *frame, int (*fn)(struct stackframe *, void *), void *data);

void show_stack1(struct task_struct *p1, void *p2)
{
#ifdef CONFIG_STACKTRACE
	struct stack_trace trace;
	unsigned long *entries;
	int i;

	entries = kmalloc(MAX_STACK_TRACE_DEPTH * sizeof(*entries), GFP_KERNEL);
	if (!entries) {
		printk("entries malloc failure\n");
		return;
	}
	trace.nr_entries = 0;
	trace.max_entries = MAX_STACK_TRACE_DEPTH;
	trace.entries = entries;
	trace.skip = 0;
	save_stack_trace_tsk(p1, &trace);

	for (i = 0; i < trace.nr_entries; i++)
		if (entries[i] != ULONG_MAX)
			save_log("%pS\n", (void *)entries[i]);
	kfree(entries);
#endif
}

///////////////////////////////////////////////////////////////////////////////////////////////////
static mm_segment_t oldfs;
static void initKernelEnv(void)
{
	oldfs = get_fs();
	set_fs(KERNEL_DS);
}

static void deinitKernelEnv(void)
{
	set_fs(oldfs);
}

static char *ASUSSlowg_filename;
char asusslowg_filepath[256];
static char *ASUSSlowgdelta_filename;
char asusslowgdelta_filepath[256];

char messages[256];
void save_phone_hang_log(int delta)
{
	int file_handle;
	int ret =  0;

	//---------------saving phone hang log if any -------------------------------
	g_phonehang_log = (char *)PHONE_HANG_LOG_BUFFER;
	printk("save_phone_hang_log PRINTK_BUFFER=%x, PHONE_HANG_LOG_BUFFER=%x\n", PRINTK_BUFFER_VA, PHONE_HANG_LOG_BUFFER);
	if (g_phonehang_log && ((strncmp(g_phonehang_log, "PhoneHang", 9) == 0) || (strncmp(g_phonehang_log, "ASUSSlowg", 9) == 0))) {
		printk("save_phone_hang_log-1\n");
		initKernelEnv();
		memset(messages, 0, sizeof(messages));
		strcpy(messages, ASUS_ASDF_BASE_DIR);

		if (delta) {
			strncat(messages, g_phonehang_log, 29 + 6);
			memset(asusslowgdelta_filepath, 0, sizeof(char)*256);
			strcpy(asusslowgdelta_filepath, messages);
			ASUSSlowgdelta_filename = asusslowgdelta_filepath;
		}
		else {
			strncat(messages, g_phonehang_log, 29);
			memset(asusslowg_filepath, 0, sizeof(char)*256);
			strcpy(asusslowg_filepath, messages);
			ASUSSlowg_filename = asusslowg_filepath;
		}
		file_handle = ksys_open(messages, O_CREAT | O_WRONLY | O_SYNC, 0);
		printk("save_phone_hang_log-2 file_handle %d, name=%s\n", file_handle, messages);
		if (!IS_ERR((const void *)(ulong)file_handle)) {
			ret = ksys_write(file_handle, (unsigned char *)g_phonehang_log, strlen(g_phonehang_log));
			ksys_close(file_handle);
		}
		deinitKernelEnv();
	}
	if (g_phonehang_log && file_handle > 0 && ret > 0)
		g_phonehang_log[0] = 0;
}
EXPORT_SYMBOL(save_phone_hang_log);

static char *LastShutdown_filename;
char lastshut_filepath[256];
void save_last_shutdown_log(char *filename)
{
	char *last_shutdown_log;
	int file_handle;
	struct rtc_time tm;

	char *last_logcat_buffer;

	int fd_kmsg_16K;
	ulong printk_buffer_index;
	ulong *printk_buffer_slot2_addr = (ulong *)PRINTK_BUFFER_SLOT2;

	asus_rtc_read_time(&tm);
	last_shutdown_log = (char *)PRINTK_BUFFER_VA;
	last_logcat_buffer = (char *)LOGCAT_BUFFER;
	sprintf(messages, ASUS_ASDF_BASE_DIR "LastShutdown_%04d%02d%02d-%02d%02d%02d.txt",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	memset(lastshut_filepath, 0, sizeof(char)*256);
	strcpy(lastshut_filepath, messages);
	LastShutdown_filename = lastshut_filepath;

	initKernelEnv();
	file_handle = ksys_open(messages, O_CREAT | O_RDWR | O_SYNC, 0);
	if (!IS_ERR((const void *)(ulong)file_handle)) {
		ksys_write(file_handle, (unsigned char *)last_shutdown_log, PRINTK_BUFFER_SLOT_SIZE);
		ksys_close(file_handle);
		printk("[ASDF] save_last_shutdown_log: evtlog_bootup_reason = %s\n", evtlog_bootup_reason);
		if (strncmp(evtlog_bootup_reason, "kernel_panic", strlen("kernel_panic")) == 0) {
			ASUSEvtlog("[Reboot] Kernel panic\n");
		}
		memset(evtlog_bootup_reason, 0, sizeof(char)*50);

	} else {
		printk("[ASDF] save_last_shutdown_error: [%d]\n", file_handle);
	}

	// ASUS_BSP +++ Jiunhau_Wang [ZE620KL][Dropbox][NA][NA] /asdf/last_kmsg_16K
	printk_buffer_index = *(printk_buffer_slot2_addr + 1);
	if ((printk_buffer_index < PRINTK_BUFFER_SLOT_SIZE) && (LAST_KMSG_SIZE < SZ_128K)) {
		fd_kmsg_16K = ksys_open("/asdf/last_kmsg_16K", O_CREAT | O_RDWR | O_SYNC, S_IRUGO);
		if (!IS_ERR((const void *)(ulong)fd_kmsg_16K)) {
			char *buf = kzalloc(LAST_KMSG_SIZE, GFP_ATOMIC);

			if (!buf) {
				printk("[ASDF] failed to allocate buffer for last_kmsg_16K\n");
			} else {
				if (printk_buffer_index > LAST_KMSG_SIZE) {
					memcpy(buf, last_shutdown_log + printk_buffer_index - LAST_KMSG_SIZE, LAST_KMSG_SIZE);
				} else {
					ulong part1 = LAST_KMSG_SIZE - printk_buffer_index;
					ulong part2 = printk_buffer_index;
					memcpy(buf, last_shutdown_log + PRINTK_BUFFER_SLOT_SIZE - part1, part1);
					memcpy(buf + part1, last_shutdown_log, part2);
				}
				ksys_write(fd_kmsg_16K, buf, LAST_KMSG_SIZE);
				kfree(buf);
			}

			ksys_close(fd_kmsg_16K);
			ksys_chmod("/asdf/last_kmsg_16K", S_IRUGO);
		} else {
			printk("[ASDF] failed to save last shutdown log to last_kmsg_16K\n");
		}
	}
// ASUS_BSP --- Jiunhau_Wang [ZE620KL][Dropbox][NA][NA] /asdf/last_kmsg_16K
	deinitKernelEnv();
}

#if 0
extern struct msm_rtb_state msm_rtb;
int g_saving_rtb_log = 1;
void save_rtb_log(void)
{
	char *rtb_log;
	char rtb_log_path[256] = { 0 };
	int file_handle;
	unsigned long long t;
	unsigned long nanosec_rem;

	rtb_log = (char *)msm_rtb.rtb;
	t = cpu_clock(0);
	nanosec_rem = do_div(t, 1000000000);
	snprintf(rtb_log_path, sizeof(rtb_log_path) - 1, ASUS_ASDF_BASE_DIR "/rtb_%lu.%06lu.bin",
		 (unsigned long)t,
		 nanosec_rem / 1000);

	initKernelEnv();
	file_handle = ksys_open(rtb_log_path, O_CREAT | O_RDWR | O_SYNC, 0);
	if (!IS_ERR((const void *)(ulong)file_handle)) {
		ksys_write(file_handle, (unsigned char *)rtb_log, msm_rtb.size);
		ksys_close(file_handle);
	} else {
		printk("[ASDF] save_rtb_log_error: [%d]\n", file_handle);
	}
	deinitKernelEnv();
}
#endif

void get_last_shutdown_log(void)
{
	ulong *printk_buffer_slot2_addr;

	printk_buffer_slot2_addr = (ulong *)PRINTK_BUFFER_SLOT2;
	printk("get_last_shutdown_log: printk_buffer_slot2=%x, value=0x%lx\n", printk_buffer_slot2_addr, *printk_buffer_slot2_addr);
	if (*printk_buffer_slot2_addr == (ulong)PRINTK_BUFFER_MAGIC)
		save_last_shutdown_log("LastShutdown");
}
EXPORT_SYMBOL(get_last_shutdown_log);

void rm_lastshut_slowg(void)
{
	ksys_unlink(ASUSSlowg_filename);
	ksys_unlink(ASUSSlowgdelta_filename);
	ksys_unlink(LastShutdown_filename);
}
EXPORT_SYMBOL(rm_lastshut_slowg);

extern int nSuspendInProgress;
static struct workqueue_struct *ASUSEvtlog_workQueue;
static int g_hfileEvtlog = -MAX_ERRNO;
static int g_bEventlogEnable = 1;

static char g_Asus_Eventlog[ASUS_EVTLOG_MAX_ITEM][ASUS_EVTLOG_STR_MAXLEN];
static int g_Asus_Eventlog_read = 0;
static int g_Asus_Eventlog_write = 0;
//[+++]Record the important power event
static struct workqueue_struct *ASUSErclog_workQueue;
static int g_hfileErclog = -MAX_ERRNO;
static char g_Asus_Erclog[ASUS_ERCLOG_MAX_ITEM][ASUS_ERCLOG_STR_MAXLEN];
static char g_Asus_Erclog_filelist[ASUS_ERCLOG_MAX_ITEM][ASUS_ERCLOG_FILENAME_MAXLEN];
static int g_Asus_Erclog_read = 0;
static int g_Asus_Erclog_write = 0;
//[---]Record the important power event

static void do_write_event_worker(struct work_struct *work);
static DECLARE_WORK(eventLog_Work, do_write_event_worker);
//[+++]Record the important power event
static void do_write_erc_worker(struct work_struct *work);
static DECLARE_WORK(ercLog_Work, do_write_erc_worker);
//[---]Record the important power event

/*ASUS-BBSP SubSys Health Record+++*/
static char g_SubSys_W_Buf[SUBSYS_W_MAXLEN];
static char g_SubSys_C_Buf[SUBSYS_C_MAXLEN]="0000-0000-0000-0000-0000";
static void do_write_subsys_worker(struct work_struct *work);
static void do_count_subsys_worker(struct work_struct *work);
static void do_delete_subsys_worker(struct work_struct *work);
static DECLARE_WORK(subsys_w_Work, do_write_subsys_worker);
static DECLARE_WORK(subsys_c_Work, do_count_subsys_worker);
static DECLARE_WORK(subsys_d_Work, do_delete_subsys_worker);
static struct completion SubSys_C_Complete;
/*ASUS-BBSP SubSys Health Record---*/

static struct mutex mA;
static struct mutex mA_erc;//Record the important power event
#define AID_SDCARD_RW 1015

static void do_write_event_worker(struct work_struct *work)
{
	char buffer[256];

	memset(buffer, 0, sizeof(char) * 256);

	initKernelEnv();

	if (IS_ERR((const void *)(ulong)g_hfileEvtlog)) {
		long size;

		g_hfileEvtlog = ksys_open(ASUS_EVTLOG_PATH ".txt", O_CREAT | O_RDWR | O_SYNC, 0666);
		ksys_chown(ASUS_EVTLOG_PATH ".txt", AID_SDCARD_RW, AID_SDCARD_RW);
		size = ksys_lseek(g_hfileEvtlog, 0, SEEK_END);
		if (size >= SZ_4M) {
			ksys_close(g_hfileEvtlog);
			ksys_link(ASUS_EVTLOG_PATH "_old.txt", ASUS_EVTLOG_PATH "_old1.txt");
			ksys_unlink(ASUS_EVTLOG_PATH "_old.txt");
			ksys_link(ASUS_EVTLOG_PATH ".txt", ASUS_EVTLOG_PATH "_old.txt");
			ksys_unlink(ASUS_EVTLOG_PATH ".txt");
			g_hfileEvtlog = ksys_open(ASUS_EVTLOG_PATH ".txt", O_CREAT | O_RDWR | O_SYNC, 0666);
		}

		ksys_write(g_hfileEvtlog, buffer, strlen(buffer));
		ksys_close(g_hfileEvtlog);
	}
	if (!IS_ERR((const void *)(ulong)g_hfileEvtlog)) {
		int str_len;
		char *pchar;
		long size;

		g_hfileEvtlog = ksys_open(ASUS_EVTLOG_PATH ".txt", O_CREAT | O_RDWR | O_SYNC, 0666);
		ksys_chown(ASUS_EVTLOG_PATH ".txt", AID_SDCARD_RW, AID_SDCARD_RW);

		size = ksys_lseek(g_hfileEvtlog, 0, SEEK_END);
		if (size >= SZ_4M) {
			ksys_close(g_hfileEvtlog);
			ksys_link(ASUS_EVTLOG_PATH "_old.txt", ASUS_EVTLOG_PATH "_old1.txt");
			ksys_unlink(ASUS_EVTLOG_PATH "_old.txt");
			ksys_link(ASUS_EVTLOG_PATH ".txt", ASUS_EVTLOG_PATH "_old.txt");
			ksys_unlink(ASUS_EVTLOG_PATH ".txt");
			g_hfileEvtlog = ksys_open(ASUS_EVTLOG_PATH ".txt", O_CREAT | O_RDWR | O_SYNC, 0666);
		}

		while (g_Asus_Eventlog_read != g_Asus_Eventlog_write) {
			mutex_lock(&mA);
			str_len = strlen(g_Asus_Eventlog[g_Asus_Eventlog_read]);
			pchar = g_Asus_Eventlog[g_Asus_Eventlog_read];
			g_Asus_Eventlog_read++;
			g_Asus_Eventlog_read %= ASUS_EVTLOG_MAX_ITEM;
			mutex_unlock(&mA);

			if (pchar[str_len - 1] != '\n') {
				if (str_len + 1 >= ASUS_EVTLOG_STR_MAXLEN)
					str_len = ASUS_EVTLOG_STR_MAXLEN - 2;
				pchar[str_len] = '\n';
				pchar[str_len + 1] = '\0';
			}

			ksys_write(g_hfileEvtlog, pchar, strlen(pchar));
			//sys_fsync(g_hfileEvtlog);
		}
		ksys_close(g_hfileEvtlog);
	}
	deinitKernelEnv();
}

//extern struct timezone sys_tz;

void ASUSEvtlog(const char *fmt, ...)
{
	va_list args;
	char *buffer;

	if (g_bEventlogEnable == 0)
		return;
	if (!in_interrupt() && !in_atomic() && !irqs_disabled())
		mutex_lock(&mA);

	buffer = g_Asus_Eventlog[g_Asus_Eventlog_write];
	g_Asus_Eventlog_write++;
	g_Asus_Eventlog_write %= ASUS_EVTLOG_MAX_ITEM;

	if (!in_interrupt() && !in_atomic() && !irqs_disabled())
		mutex_unlock(&mA);

	memset(buffer, 0, ASUS_EVTLOG_STR_MAXLEN);
	if (buffer) {
		struct rtc_time tm;
		struct timespec ts;

		getnstimeofday(&ts);
		ts.tv_sec -= sys_tz.tz_minuteswest * 60;
		rtc_time_to_tm(ts.tv_sec, &tm);
		getrawmonotonic(&ts);
		sprintf(buffer, "(%ld)%04d-%02d-%02d %02d:%02d:%02d :", ts.tv_sec, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
		va_start(args, fmt);
		vscnprintf(buffer + strlen(buffer), ASUS_EVTLOG_STR_MAXLEN - strlen(buffer), fmt, args);
		va_end(args);
		printk("%s", buffer);
		queue_work(ASUSEvtlog_workQueue, &eventLog_Work);
	} else {
		printk("ASUSEvtlog buffer cannot be allocated\n");
	}
}
EXPORT_SYMBOL(ASUSEvtlog);

/*
 * Record the important power event
 */
static void do_write_erc_worker(struct work_struct *work)
{
    int str_len;
    char log_body[ASUS_ERCLOG_STR_MAXLEN];
    char filepath[ASUS_ERCLOG_FILENAME_MAXLEN];
    char filepath_old[ASUS_ERCLOG_FILENAME_MAXLEN];
    long size;
    int flag_read = -1;
    int flag_write = -1;

    while (g_Asus_Erclog_read != g_Asus_Erclog_write) {
        memset(log_body, 0, ASUS_ERCLOG_STR_MAXLEN);
        memset(filepath, 0, sizeof(char)*ASUS_ERCLOG_FILENAME_MAXLEN);
        memset(filepath_old, 0, sizeof(char)*ASUS_ERCLOG_FILENAME_MAXLEN);

        mutex_lock(&mA_erc);
        flag_read = g_Asus_Erclog_read;
        flag_write = g_Asus_Erclog_write;

        memcpy(log_body, g_Asus_Erclog[g_Asus_Erclog_read], ASUS_ERCLOG_STR_MAXLEN);
        snprintf(filepath, ASUS_ERCLOG_FILENAME_MAXLEN, "%s%s.txt", ASUS_ASDF_BASE_DIR, g_Asus_Erclog_filelist[g_Asus_Erclog_read]);
        snprintf(filepath_old, ASUS_ERCLOG_FILENAME_MAXLEN, "%s%s_old.txt", ASUS_ASDF_BASE_DIR, g_Asus_Erclog_filelist[g_Asus_Erclog_read]);
        memset(g_Asus_Erclog[g_Asus_Erclog_read], 0, ASUS_ERCLOG_STR_MAXLEN);
        memset(g_Asus_Erclog_filelist[g_Asus_Erclog_read], 0, ASUS_ERCLOG_FILENAME_MAXLEN);

        g_Asus_Erclog_read++;
        g_Asus_Erclog_read %= ASUS_ERCLOG_MAX_ITEM;
        mutex_unlock(&mA_erc);

        str_len = strlen(log_body);
		if(str_len == 0) continue;
        if (str_len > 0 && log_body[str_len - 1] != '\n' ) {
            if(str_len + 1 >= ASUS_ERCLOG_STR_MAXLEN)
                str_len = ASUS_ERCLOG_STR_MAXLEN - 2;
            log_body[str_len] = '\n';
            log_body[str_len + 1] = '\0';
        }

        pr_debug("flag_read = %d, flag_write = %d, filepath = %s\n", flag_read, flag_write, filepath);
        g_hfileErclog = ksys_open(filepath, O_CREAT|O_RDWR|O_SYNC, 0666);
        ksys_chown(filepath, AID_SDCARD_RW, AID_SDCARD_RW);

        if (!IS_ERR((const void *)(ulong)g_hfileEvtlog)) {
            size = ksys_lseek(g_hfileErclog, 0, SEEK_END);
            if (size >= 5000) {    //limit 5KB each file
                ksys_close(g_hfileErclog);
                ksys_rmdir(filepath_old);
                ksys_link(filepath, filepath_old);
                g_hfileErclog = ksys_open(filepath, O_CREAT|O_RDWR|O_SYNC, 0666);
            }

            ksys_write(g_hfileErclog, log_body, strlen(log_body));
            //sys_fsync(g_hfileErclog);
            ksys_close(g_hfileErclog);

        }else{
            pr_err("ksys_open %s IS_ERR error code: %d]\n", filepath, g_hfileEvtlog);
        }
    }
}

void ASUSErclog(const char * filename, const char *fmt, ...)
{
    va_list args;
    char *buffer;
    char *tofile;
    int flag_write = -1;

//    if (!in_interrupt() && !in_atomic() && !irqs_disabled())
        mutex_lock(&mA_erc);

    flag_write = g_Asus_Erclog_write;
    buffer = g_Asus_Erclog[g_Asus_Erclog_write];
    tofile = g_Asus_Erclog_filelist[g_Asus_Erclog_write];
    memset(buffer, 0, ASUS_EVTLOG_STR_MAXLEN);
    memset(tofile, 0, ASUS_ERCLOG_FILENAME_MAXLEN);
    g_Asus_Erclog_write++;
    g_Asus_Erclog_write %= ASUS_EVTLOG_MAX_ITEM;

//    if (!in_interrupt() && !in_atomic() && !irqs_disabled())
        mutex_unlock(&mA_erc);

    if (buffer) {
        struct rtc_time tm;
        struct timespec ts;

        getnstimeofday(&ts);
        ts.tv_sec -= sys_tz.tz_minuteswest * 60;
        rtc_time_to_tm(ts.tv_sec, &tm);
        getrawmonotonic(&ts);
        sprintf(buffer, "%04d%02d%02d%02d%02d%02d :", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

        va_start(args, fmt);
        vscnprintf(buffer + strlen(buffer), ASUS_ERCLOG_STR_MAXLEN - strlen(buffer), fmt, args);
        va_end(args);
	printk("%s", buffer);
        sprintf(tofile, "%s", filename);
        pr_debug("flag_write= %d, tofile = %s\n", flag_write, tofile);
        queue_work(ASUSErclog_workQueue, &ercLog_Work);
    } else {
        pr_err("[ASDF]ASUSErclog buffer cannot be allocated\n");
    }
}
EXPORT_SYMBOL(ASUSErclog);

/*
 * SubSys Health Record
 */
static void do_write_subsys_worker(struct work_struct *work)
{
	int hfile = -MAX_ERRNO;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

	hfile = ksys_open(SUBSYS_HEALTH_MEDICAL_TABLE_PATH".txt", O_CREAT|O_WRONLY|O_SYNC, 0666);
	if(!IS_ERR((const void *)(ulong)hfile)) {
		if (ksys_lseek(hfile, 0, SEEK_END) >= SZ_128K) {
			ASUSEvtlog("[SSR-Info] SubSys is versy ill\n");
			ksys_close(hfile);
			ksys_unlink(SUBSYS_HEALTH_MEDICAL_TABLE_PATH"_old.txt");
			ksys_link(SUBSYS_HEALTH_MEDICAL_TABLE_PATH".txt", SUBSYS_HEALTH_MEDICAL_TABLE_PATH"_old.txt");
			hfile = ksys_open(SUBSYS_HEALTH_MEDICAL_TABLE_PATH".txt", O_CREAT|O_RDWR|O_SYNC, 0666);
		}
		ksys_write(hfile, g_SubSys_W_Buf, strlen(g_SubSys_W_Buf));
		//sys_fsync(hfile);
		ksys_close(hfile);
	} else {
		ASUSEvtlog("[SSR-Info] Save SubSys Medical Table Error: [0x%x]\n", hfile);
		ksys_unlink(SUBSYS_HEALTH_MEDICAL_TABLE_PATH".txt");/*Delete The File Which is Opened in Address Space Mismatch*/
	}
	set_fs(old_fs);
}

static void do_count_subsys_worker(struct work_struct *work)
{
	int  hfile = -MAX_ERRNO;
	char r_buf[SUBSYS_R_MAXLEN];
	int  r_size = 0;
	int  index = 0;
	char keys[] = "[SSR]:";
	char *pch;
	char n_buf[64];
	char SubSysName[SUBSYS_NUM_MAX][10];
	int  Counts[SUBSYS_NUM_MAX] = { 0 };
	int  subsys_num = 0;
	char OutSubSysName[3][10] = { "modem", "no_wifi", "adsp" };/* Confirm SubSys Name for Each Platform */
	int  OutCounts[4] = { 0 };/* MODEM, WIFI, ADSP, OTHERS */
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

	/* Search All SubSys Supported */
	for(index = 0 ; index < SUBSYS_NUM_MAX ; index++) {
		sprintf(n_buf, SUBSYS_BUS_ROOT"/subsys%d/name", index);
		hfile = ksys_open(n_buf, O_RDONLY|O_SYNC, 0444);
		if(!IS_ERR((const void *)(ulong)hfile)) {
			memset(r_buf, 0, sizeof(r_buf));
			r_size = ksys_read(hfile, r_buf, sizeof(r_buf));
			if (r_size > 0) {
				sprintf(SubSysName[index], r_buf, r_size-2);/* Skip \n\0 */
				SubSysName[index][r_size-1] = '\0';/* Insert \0 at last */
				subsys_num++;
			}
			ksys_close(hfile);
		}
	}

	hfile = ksys_open(SUBSYS_HEALTH_MEDICAL_TABLE_PATH".txt", O_CREAT|O_RDONLY|O_SYNC, 0444);
	if(!IS_ERR((const void *)(ulong)hfile)) {
		do {
			memset(r_buf, 0, sizeof(r_buf));
			r_size = ksys_read(hfile, r_buf, sizeof(r_buf));
			if (r_size != 0) {
				/* count */
				pch = strstr(r_buf, keys);
				while (pch != NULL) {
					pch = pch + strlen(keys);
					for (index = 0 ; index < subsys_num ; index++) {
						if (!strncmp(pch, SubSysName[index], strlen(SubSysName[index]))) {
							Counts[index]++;
							break;
						}
					}
					pch = strstr(pch, keys);
				}
			}
		} while (r_size != 0);

		ksys_close(hfile);
	}

	hfile = ksys_open(SUBSYS_HEALTH_MEDICAL_TABLE_PATH"_old.txt", O_RDONLY|O_SYNC, 0444);
	if(!IS_ERR((const void *)(ulong)hfile)) {
		do {
			memset(r_buf, 0, sizeof(r_buf));
			r_size = ksys_read(hfile, r_buf, sizeof(r_buf));
			if (r_size != 0) {
				/* count */
				pch = strstr(r_buf, keys);
				while (pch != NULL) {
					pch = pch + strlen(keys);
					for (index = 0 ; index < subsys_num ; index++) {
						if (!strncmp(pch, SubSysName[index], strlen(SubSysName[index]))) {
							Counts[index]++;
							break;
						}
					}
					pch = strstr(pch, keys);
				}
			}
		} while (r_size != 0);

		ksys_close(hfile);
	}

	/* Map The Out Pattern */
	for(index = 0 ; index < subsys_num ; index++) {
		if (!strncmp(OutSubSysName[0], SubSysName[index], strlen(SubSysName[index]))) {
			OutCounts[0] += Counts[index]; /* MODEM */
		} else if (!strncmp(OutSubSysName[1], SubSysName[index], strlen(SubSysName[index]))) {
			OutCounts[1] += Counts[index]; /* WIFI */
		} else if (!strncmp(OutSubSysName[2], SubSysName[index], strlen(SubSysName[index]))) {
			OutCounts[2] += Counts[index]; /* ADSP */
		} else {
			OutCounts[3] += Counts[index]; /* OTHERS */
		}
	}

	hfile = ksys_open("/asdf/reboot_count", O_RDONLY|O_SYNC, 0);
	memset(r_buf, 0, sizeof(r_buf));
	if (!IS_ERR((const void *)(ulong)hfile)) {
		ksys_read(hfile, r_buf, sizeof(r_buf));
		ksys_close(hfile);
	} else {
		strcpy(r_buf, "0");
	}
	set_fs(old_fs);

	sprintf(g_SubSys_C_Buf, "%s-%d-%d-%d-%d", r_buf, OutCounts[0], OutCounts[1], OutCounts[2], OutCounts[3]);/* MODEM, WIFI, ADSP, OTHERS */
	complete(&SubSys_C_Complete);
}

static void do_delete_subsys_worker(struct work_struct *work)
{
	ksys_unlink(SUBSYS_HEALTH_MEDICAL_TABLE_PATH".txt");
	ksys_unlink(SUBSYS_HEALTH_MEDICAL_TABLE_PATH"_old.txt");
	ASUSEvtlog("[SSR-Info] SubSys Medical Table Deleted\n");
}

void SubSysHealthRecord(const char *fmt, ...)
{
	va_list args;
	char *w_buf;
	struct rtc_time tm;
	struct timespec ts;

	memset(g_SubSys_W_Buf, 0 , sizeof(g_SubSys_W_Buf));
	w_buf = g_SubSys_W_Buf;

	getnstimeofday(&ts);
	ts.tv_sec -= sys_tz.tz_minuteswest * 60;
	rtc_time_to_tm(ts.tv_sec, &tm);
	sprintf(w_buf, "%04d-%02d-%02d %02d:%02d:%02d : ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	va_start(args, fmt);
	vscnprintf(w_buf + strlen(w_buf), sizeof(g_SubSys_W_Buf) - strlen(w_buf), fmt, args);
	va_end(args);
	/*printk("g_SubSys_W_Buf = %s", g_SubSys_W_Buf);*/

	queue_work(ASUSEvtlog_workQueue, &subsys_w_Work);
}
EXPORT_SYMBOL(SubSysHealthRecord);

static int SubSysHealth_proc_show(struct seq_file *m, void *v)
{
	unsigned long ret;

	queue_work(ASUSEvtlog_workQueue, &subsys_c_Work);/* Issue to count */

	ret = wait_for_completion_timeout(&SubSys_C_Complete, msecs_to_jiffies(1000));
	if (!ret)
		ASUSEvtlog("[SSR-Info] Timed out on query SubSys count\n");

	seq_printf(m, "%s\n", g_SubSys_C_Buf);
	return 0;
}

static int SubSysHealth_proc_open(struct inode *inode, struct  file *file)
{
	return single_open(file, SubSysHealth_proc_show, NULL);
}

static ssize_t SubSysHealth_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char keyword[] = "clear";
	char tmpword[10];
	memset(tmpword, 0, sizeof(tmpword));

	/* no data be written Or Input size is too large to write our buffer */
	if ((!count) || (count > (sizeof(tmpword) - 1)))
		return -EINVAL;

	if (copy_from_user(tmpword, buf, count))
		return -EFAULT;

	if (strncmp(tmpword, keyword, strlen(keyword)) == 0) {
		queue_work(ASUSEvtlog_workQueue, &subsys_d_Work);
	}

	return count;
}

static const struct file_operations proc_SubSysHealth_operations = {
	.open = SubSysHealth_proc_open,
	.read = seq_read,
	.write = SubSysHealth_proc_write,
};

static ssize_t evtlogswitch_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	if (strncmp(buf, "0", 1) == 0) {
		ASUSEvtlog("ASUSEvtlog disable !!");
		printk("ASUSEvtlog disable !!\n");
		flush_work(&eventLog_Work);
		g_bEventlogEnable = 0;
	}
	if (strncmp(buf, "1", 1) == 0) {
		g_bEventlogEnable = 1;
		ASUSEvtlog("ASUSEvtlog enable !!");
		printk("ASUSEvtlog enable !!\n");
	}

	return count;
}
static ssize_t asusevtlog_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	if (count > 256)
		count = 256;

	memset(messages, 0, sizeof(messages));
	if (copy_from_user(messages, buf, count))
		return -EFAULT;

	ASUSEvtlog("%s", messages);

	return count;
}

/*
 * For asusdebug
 */
static int asusdebug_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int asusdebug_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t asusdebug_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	return 0;
}

#include <linux/reboot.h>
extern int rtc_ready;
int asus_asdf_set = 0;
static ssize_t asusdebug_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	u8 messages[256] = { 0 };

	if (count > 256)
		count = 256;
	if (copy_from_user(messages, buf, count))
		return -EFAULT;

	if (strncmp(messages, "panic", strlen("panic")) == 0) {
		panic("panic test");
	} else if (strncmp(messages, "dbg", strlen("dbg")) == 0) {
		g_user_dbg_mode = 1;
		printk("Kernel dbg mode = %d\n", g_user_dbg_mode);
	} else if (strncmp(messages, "ndbg", strlen("ndbg")) == 0) {
		g_user_dbg_mode = 0;
		printk("Kernel dbg mode = %d\n", g_user_dbg_mode);
	} else if (strncmp(messages, "get_asdf_log",
			   strlen("get_asdf_log")) == 0) {
		ulong *printk_buffer_slot2_addr;

		printk_buffer_slot2_addr = (ulong *)PRINTK_BUFFER_SLOT2;
		printk("[ASDF] printk_buffer_slot2_addr=%x, value=0x%lx\n", printk_buffer_slot2_addr, *printk_buffer_slot2_addr);

		if (!asus_asdf_set) {
			asus_asdf_set = 1;
			save_phone_hang_log(1);
			get_last_shutdown_log();
			printk("[ASDF] get_last_shutdown_log: printk_buffer_slot2_addr=%x, value=0x%lx\n", printk_buffer_slot2_addr, *printk_buffer_slot2_addr);
#if 0
			if ((*printk_buffer_slot2_addr) == (ulong)PRINTK_BUFFER_MAGIC)
				save_rtb_log();
#endif
			if ((*printk_buffer_slot2_addr) == (ulong)PRINTK_BUFFER_MAGIC) {
				printk("[ASDF] ksys_sync after saving asdf log\n");
				initKernelEnv();
				printk("[ASDF] asusdebug: initKernelEnv\n");
				ksys_sync();
				printk("[ASDF] asusdebug: ksys_sync\n");
				deinitKernelEnv();
				printk("[ASDF] asusdebug: deinitKernelEnv\n");
				//qpnp_pon_system_pwr_off(PON_POWER_OFF_HARD_RESET);
				//kernel_restart("save lastshutdown");
			}

			(*printk_buffer_slot2_addr) = (ulong)PRINTK_BUFFER_MAGIC;
			printk("[ASDF] set printk_buffer_slot2_addr=%x, value=0x%lx\n", printk_buffer_slot2_addr, *printk_buffer_slot2_addr);
		}
#if 0
		g_saving_rtb_log = 0;
#endif
	} else if (strncmp(messages, "slowlog", strlen("slowlog")) == 0) {
		printk("start to gi chk\n");
		save_phone_hang_log(0);
		msleep(5 * 1000);

		printk("start to gi delta\n");
		save_phone_hang_log(1);
		return count;
	}

	return count;
}

static const struct file_operations proc_evtlogswitch_operations = {
	.write	= evtlogswitch_write,
};
static const struct file_operations proc_asusevtlog_operations = {
	.write	= asusevtlog_write,
};
static const struct file_operations proc_asusdebug_operations = {
	.read		= asusdebug_read,
	.write		= asusdebug_write,
	.open		= asusdebug_open,
	.release	= asusdebug_release,
};
static const struct file_operations proc_asusdebugprop_operations = {
	.read	   = asusdebug_read,
	.write	  = asusdebug_write,
	.open	   = asusdebug_open,
	.release	= asusdebug_release,
};

/*
 * ASUS LogUnlock
 */
static ssize_t logunlock_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t logunlock_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char messages[256];
	int file_handle;

	memset(messages, 0, sizeof(char)*256);

	if (count > 256)
		count = 256;
	if (copy_from_user(messages, buf, count))
		return -EFAULT;

	initKernelEnv();
	file_handle = ksys_open(ASUS_ASDF_BASE_DIR "LogUnlock.txt", O_CREAT | O_RDWR | O_SYNC, 0660);
	if (!IS_ERR((const void *)(ulong)file_handle)) {
		ksys_write(file_handle, messages, strlen(messages));
		ksys_close(file_handle);
	}else {
		printk("[LogTool] logunlock write error: [%d]\n", file_handle);
	}
	deinitKernelEnv();

	return count;
}

static const struct file_operations proc_logunlock_operations = {
	.read	= logunlock_read,
	.write	= logunlock_write,
};


#ifdef CONFIG_HAS_EARLYSUSPEND
static void asusdebug_early_suspend(struct early_suspend *h)
{
	entering_suspend = 1;
}

static void asusdebug_early_resume(struct early_suspend *h)
{
	entering_suspend = 0;
}
EXPORT_SYMBOL(entering_suspend);

struct early_suspend asusdebug_early_suspend_handler = {
	.level		= EARLY_SUSPEND_LEVEL_BLANK_SCREEN,
	.suspend	= asusdebug_early_suspend,
	.resume		= asusdebug_early_resume,
};
#endif

unsigned int asusdebug_enable = 0;
unsigned int readflag = 0;
static ssize_t turnon_asusdebug_proc_read(struct file *filp, char __user *buff, size_t len, loff_t *off)
{
	char print_buf[32];
	unsigned int ret = 0, iret = 0;

	sprintf(print_buf, "asusdebug: %s\n", asusdebug_enable ? "off" : "on");
	ret = strlen(print_buf);
	iret = copy_to_user(buff, print_buf, ret);
	if (!readflag) {
		readflag = 1;
		return ret;
	} else {
		readflag = 0;
		return 0;
	}
}
static ssize_t turnon_asusdebug_proc_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
	char messages[256];

	memset(messages, 0, sizeof(messages));
	if (len > 256)
		len = 256;
	if (copy_from_user(messages, buff, len))
		return -EFAULT;
	if (strncmp(messages, "off", 3) == 0)
		asusdebug_enable = 0x11223344;
	else if (strncmp(messages, "on", 2) == 0)
		asusdebug_enable = 0;
	return len;
}
static struct file_operations turnon_asusdebug_proc_ops = {
	.read	= turnon_asusdebug_proc_read,
	.write	= turnon_asusdebug_proc_write,
};

static ssize_t last_logcat_proc_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
	char messages[1024];
	char *last_logcat_buffer;

	memset(messages, 0, sizeof(messages));

	if (len > 1024)
		len = 1024;
	if (copy_from_user(messages, buff, len))
		return -EFAULT;

	last_logcat_buffer = (char *)LOGCAT_BUFFER;

	if (logcat_buffer_index + len >= LOGCAT_BUFFER_SIZE) {
		ulong part1 = LOGCAT_BUFFER_SIZE - logcat_buffer_index;
		ulong part2 = len - part1;
		memcpy_nc(last_logcat_buffer + logcat_buffer_index, messages, part1);
		memcpy_nc(last_logcat_buffer, messages + part1, part2);
		logcat_buffer_index = part2;
	} else {
		memcpy_nc(last_logcat_buffer + logcat_buffer_index, messages, len);
		logcat_buffer_index += len;
	}

	return len;
}

static struct file_operations last_logcat_proc_ops = {
	.write = last_logcat_proc_write,
};

/*
 * Minidump Log - LastShutdownCrash & LastShutdownLogcat
 */
static void register_minidump_log_buf(void)
{
	struct md_region md_entry;

	/*Register logbuf to minidump, first idx would be from bss section */
	strlcpy(md_entry.name, "KLOGDMSG", sizeof(md_entry.name));
	md_entry.virt_addr = (uintptr_t) (PRINTK_BUFFER_VA);
	md_entry.phys_addr = (uintptr_t) (PRINTK_BUFFER_PA);
	md_entry.size = PRINTK_BUFFER_SLOT_SIZE;
	if (msm_minidump_add_region(&md_entry))
		pr_err("Failed to add logbuf in Minidump\n");

	strlcpy(md_entry.name, "KLLOGCAT", sizeof(md_entry.name));
	md_entry.virt_addr = (uintptr_t) (LOGCAT_BUFFER);
	md_entry.phys_addr = (uintptr_t) (LOGCAT_BUFFER_PA);
	md_entry.size = LOGCAT_BUFFER_SIZE;
	if (msm_minidump_add_region(&md_entry))
		pr_err("Failed to add logbuf in Minidump\n");
}

static int __init proc_asusdebug_init(void)
{
	proc_create("asusdebug", S_IALLUGO, NULL, &proc_asusdebug_operations);
	proc_create("asusdebug-prop", S_IALLUGO, NULL, &proc_asusdebugprop_operations);
	proc_create("asusevtlog", S_IRWXUGO, NULL, &proc_asusevtlog_operations);
	proc_create("asusevtlog-switch", S_IRWXUGO, NULL, &proc_evtlogswitch_operations);
	proc_create("asusdebug-switch", S_IRWXUGO, NULL, &turnon_asusdebug_proc_ops);
	proc_create("last_logcat", S_IWUGO, NULL, &last_logcat_proc_ops);
	proc_create("logunlock", S_IRWXUGO, NULL, &proc_logunlock_operations);

	PRINTK_BUFFER_VA = ioremap(PRINTK_BUFFER_PA, PRINTK_BUFFER_SIZE);
	register_minidump_log_buf();
	mutex_init(&mA);
	mutex_init(&mA_erc);//Record the important power event
	fake_rtmutex.owner = current;

	/*ASUS-BBSP SubSys Health Record+++*/
	proc_create("SubSysHealth", S_IRWXUGO, NULL, &proc_SubSysHealth_operations);
	init_completion(&SubSys_C_Complete);
	/*ASUS-BBSP SubSys Health Record---*/

	ASUSEvtlog_workQueue = create_singlethread_workqueue("ASUSEVTLOG_WORKQUEUE");
	ASUSErclog_workQueue  = create_singlethread_workqueue("ASUSERCLOG_WORKQUEUE");//Record the important power event

#ifdef CONFIG_HAS_EARLYSUSPEND
	register_early_suspend(&asusdebug_early_suspend_handler);
#endif

	return 0;
}
module_init(proc_asusdebug_init);

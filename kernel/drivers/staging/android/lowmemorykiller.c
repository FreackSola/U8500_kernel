/* drivers/misc/lowmemorykiller.c
 *
 * The lowmemorykiller driver lets user-space specify a set of memory thresholds
 * where processes with a range of oom_adj values will get killed. Specify the
 * minimum oom_adj values in /sys/module/lowmemorykiller/parameters/adj and the
 * number of free pages in /sys/module/lowmemorykiller/parameters/minfree. Both
 * files take a comma separated list of numbers in ascending order.
 *
 * For example, write "0,8" to /sys/module/lowmemorykiller/parameters/adj and
 * "1024,4096" to /sys/module/lowmemorykiller/parameters/minfree to kill processes
 * with a oom_adj value of 8 or higher when the free memory drops below 4096 pages
 * and kill processes with a oom_adj value of 0 or higher when the free memory
 * drops below 1024 pages.
 *
 * The driver considers memory used for caches to be free, but if a large
 * percentage of the cached memory is locked this can be very inaccurate
 * and processes may not get killed until the normal oom killer is triggered.
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/notifier.h>
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_DO_NOT_KILL_PROCESS
#include <linux/string.h>
#endif
#include <linux/swap.h>
#if defined (CONFIG_SWAP) && (defined (CONFIG_ZSWAP) || defined (CONFIG_ZRAM))
#include <linux/fs.h>
#endif
#ifdef CONFIG_HIGHMEM

#define _ZONE ZONE_HIGHMEM
#else
#define _ZONE ZONE_NORMAL
#endif

static uint32_t lowmem_debug_level = 1;
static int lowmem_adj[6] = {
	0,
	3,
	5,
	9,
	11,
	15,
};
static int lowmem_adj_size = 6;
static int lowmem_minfree[6] = {
	2048,
	4096,
	12800,
	14080,
	15360,
	19200,
};
static int lowmem_minfree_size = 6;
static int lmk_fast_run = 1;

static struct task_struct *lowmem_deathpending;
static unsigned long lowmem_deathpending_timeout;

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
extern int param_array_set(const char *val, struct kernel_param *kp);
extern int param_array_get(char *buffer, struct kernel_param *kp);

static int auto_detect = 1;
static int init_kobject(void);

#endif

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_DO_NOT_KILL_PROCESS
#define MAX_NOT_KILLABLE_PROCESSES	25	/* Max number of not killable processes */
#define MANAGED_PROCESS_TYPES	3	/* Numer of managed process types (lowmem_process_type) */

/*
 * Enumerator for the managed process types
 */
enum lowmem_process_type {
	KILLABLE_PROCESS,
	DO_NOT_KILL_PROCESS,
	DO_NOT_KILL_SYSTEM_PROCESS
};

/*
 * Data struct for the management of not killable processes
 */
struct donotkill {
	uint enabled;
	char *names[MAX_NOT_KILLABLE_PROCESSES];
	int names_count;
};

static struct donotkill donotkill_proc;		/* User processes to preserve from killing */
static struct donotkill donotkill_sysproc;	/* System processes to preserve from killing */

/*
 * Checks if a process name is inside a list of processes to be preserved from killing
 */
static bool is_in_donotkill_list(char *proc_name, struct donotkill *donotkill_proc)
{
	int i = 0;

	/* If the do not kill feature is enabled and the process names to be preserved
	 * is not empty, then check if the passed process name is contained inside it */
	if (donotkill_proc->enabled && donotkill_proc->names_count > 0) {
		for (i = 0; i < donotkill_proc->names_count; i++) {
			if (strstr(donotkill_proc->names[i], proc_name) != NULL)
				return true; /* The process must be preserved from killing */
		}
	}

	return false; /* The process is not contained inside the process names list */
}

/*
 * Checks if a process name is inside a list of user processes to be preserved from killing
 */
static bool is_in_donotkill_proc_list(char *proc_name)
{
	return is_in_donotkill_list(proc_name, &donotkill_proc);
}

/*
 * Checks if a process name is inside a list of system processes to be preserved from killing
 */
static bool is_in_donotkill_sysproc_list(char *proc_name)
{
	return is_in_donotkill_list(proc_name, &donotkill_sysproc);
}
#else
#define MANAGED_PROCESS_TYPES		1	/* Numer of managed process types (lowmem_process_type) */

/*
 * Enumerator for the managed process types
 */
enum lowmem_process_type {
	KILLABLE_PROCESS
};
#endif

#define lowmem_print(level, x...)			\
	do {						\
		if (lowmem_debug_level >= (level))	\
			printk(x);			\
	} while (0)
void tune_lmk_zone_param(struct zonelist *zonelist, int classzone_idx,
					int *other_free, int *other_file)
{
	struct zone *zone;
	struct zoneref *zoneref;
	int zone_idx;

	for_each_zone_zonelist(zone, zoneref, zonelist, MAX_NR_ZONES) {
		if ((zone_idx = zonelist_zone_idx(zoneref)) == ZONE_MOVABLE)
			continue;

		if (zone_idx > classzone_idx) {
			if (other_free != NULL)
				*other_free -= zone_page_state(zone,
							       NR_FREE_PAGES);
			if (other_file != NULL)
				*other_file -= zone_page_state(zone,
							       NR_FILE_PAGES)
					      - zone_page_state(zone, NR_SHMEM);
		} else if (zone_idx < classzone_idx) {
			if (zone_watermark_ok(zone, 0, 0, classzone_idx, 0))
				*other_free -=
				           zone->lowmem_reserve[classzone_idx];
			else
				*other_free -=
				           zone_page_state(zone, NR_FREE_PAGES);
		}
	}
}

void tune_lmk_param(int *other_free, int *other_file, struct shrink_control *sc)
{
	gfp_t gfp_mask;
	struct zone *preferred_zone;
	struct zonelist *zonelist;
	enum zone_type high_zoneidx, classzone_idx;
	unsigned long balance_gap;

	gfp_mask = sc->gfp_mask;
	zonelist = node_zonelist(0, gfp_mask);
	high_zoneidx = gfp_zone(gfp_mask);
	first_zones_zonelist(zonelist, high_zoneidx, NULL, &preferred_zone);
	classzone_idx = zone_idx(preferred_zone);

	balance_gap = min(low_wmark_pages(preferred_zone),
			  (preferred_zone->present_pages +
			   KSWAPD_ZONE_BALANCE_GAP_RATIO-1) /
			   KSWAPD_ZONE_BALANCE_GAP_RATIO);

	if (likely(current_is_kswapd() && zone_watermark_ok(preferred_zone, 0,
			  high_wmark_pages(preferred_zone) + SWAP_CLUSTER_MAX +
			  balance_gap, 0, 0))) {
		if (lmk_fast_run)
			tune_lmk_zone_param(zonelist, classzone_idx, other_free,
				       other_file);
		else
			tune_lmk_zone_param(zonelist, classzone_idx, other_free,
				       NULL);

		if (zone_watermark_ok(preferred_zone, 0, 0, _ZONE, 0))
			*other_free -=
			           preferred_zone->lowmem_reserve[_ZONE];
		else
			*other_free -= zone_page_state(preferred_zone,
						      NR_FREE_PAGES);
		lowmem_print(4, "lowmem_shrink of kswapd tunning for highmem "
			     "ofree %d, %d\n", *other_free, *other_file);
	} else {
		tune_lmk_zone_param(zonelist, classzone_idx, other_free,
			       other_file);

		lowmem_print(4, "lowmem_shrink tunning for others ofree %d, "
			     "%d\n", *other_free, *other_file);
	}
}

static int
task_notify_func(struct notifier_block *self, unsigned long val, void *data);

static struct notifier_block task_nb = {
	.notifier_call	= task_notify_func,
};

static int
task_notify_func(struct notifier_block *self, unsigned long val, void *data)
{
	struct task_struct *task = data;

	if (task == lowmem_deathpending)
		lowmem_deathpending = NULL;

	return NOTIFY_OK;
}

static int lowmem_shrink(struct shrinker *s, struct shrink_control *sc)
{
	struct task_struct *tsk;
	struct task_struct *selected[MANAGED_PROCESS_TYPES] = {NULL};
	int rem = 0;
	int tasksize;
	int i;
	int min_adj = OOM_ADJUST_MAX + 1;
	int minfree = 0;
	enum lowmem_process_type proc_type = KILLABLE_PROCESS;
	int selected_tasksize[MANAGED_PROCESS_TYPES] = {0};
	int selected_oom_adj[MANAGED_PROCESS_TYPES];
	int array_size = ARRAY_SIZE(lowmem_adj);
	int other_free;
	int other_file;
	#if defined (CONFIG_SWAP) && (defined (CONFIG_ZSWAP) || defined (CONFIG_ZRAM))
	struct sysinfo si;
	#endif

	/*
	 * If we already have a death outstanding, then
	 * bail out right away; indicating to vmscan
	 * that we have nothing further to offer on
	 * this pass.
	 *
	 */
	if (lowmem_deathpending &&
	    time_before_eq(jiffies, lowmem_deathpending_timeout))
		return 0;

#if defined (CONFIG_SWAP) && (defined (CONFIG_ZSWAP) || defined (CONFIG_ZRAM))
	si_swapinfo(&si);
	other_free = global_page_state(NR_FREE_PAGES);
	other_file = global_page_state(NR_FILE_PAGES) -
						global_page_state(NR_SHMEM) +
						(si.totalswap >> 2) -
						total_swapcache_pages;
#else
 	other_free = global_page_state(NR_FREE_PAGES);
 	other_file = global_page_state(NR_FILE_PAGES) -
 						global_page_state(NR_SHMEM);
#endif

	tune_lmk_param(&other_free, &other_file, sc);
	//pr_info("LMK: tuned other_free: %d\n", other_free);
	//pr_info("LMK: tuned other_file: %d\n", other_file);

	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;
	if (lowmem_minfree_size < array_size)
		array_size = lowmem_minfree_size;
	for (i = 0; i < array_size; i++) {
		if (other_free < lowmem_minfree[i] &&
		    other_file < lowmem_minfree[i]) {
			min_adj = lowmem_adj[i];
			break;
		}
	}
	if (sc->nr_to_scan > 0)
		lowmem_print(3, "lowmem_shrink %lu, %x, ofree %d %d, ma %d\n",
			     sc->nr_to_scan, sc->gfp_mask, other_free, other_file,
			     min_adj);
	rem = global_page_state(NR_ACTIVE_ANON) +
		global_page_state(NR_ACTIVE_FILE) +
		global_page_state(NR_INACTIVE_ANON) +
		global_page_state(NR_INACTIVE_FILE);
	if (sc->nr_to_scan <= 0 || min_adj == OOM_ADJUST_MAX + 1) {
		lowmem_print(5, "lowmem_shrink %lu, %x, return %d\n",
			     sc->nr_to_scan, sc->gfp_mask, rem);
		return rem;
	}
	/* Set the initial oom_adj for each managed process type */
	for (proc_type = KILLABLE_PROCESS; proc_type < MANAGED_PROCESS_TYPES; proc_type++)
		selected_oom_adj[proc_type] = min_adj;

	rcu_read_lock();
	for_each_process(tsk) {
		struct task_struct *p;
		int oom_adj;

		if (tsk->flags & PF_KTHREAD)
			continue;

		p = find_lock_task_mm(tsk);
		if (!p)
			continue;
		oom_adj = p->signal->oom_adj;
		if (oom_adj < min_adj) {
			task_unlock(p);
			continue;
		}
		tasksize = get_mm_rss(p->mm);
		task_unlock(p);
		if (tasksize <= 0)
			continue;

		/* Initially consider the process as killable */
		proc_type = KILLABLE_PROCESS;

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_DO_NOT_KILL_PROCESS
		/* Check if the process name is contained inside the process to be preserved lists */
		if (is_in_donotkill_proc_list(p->comm)) {
			/* This user process must be preserved from killing */
			proc_type = DO_NOT_KILL_PROCESS;
			lowmem_print(2, "The process '%s' is inside the donotkill_proc_names", p->comm);
		} else if (is_in_donotkill_sysproc_list(p->comm)) {
			/* This system process must be preserved from killing */
			proc_type = DO_NOT_KILL_SYSTEM_PROCESS;
			lowmem_print(2, "The process '%s' is inside the donotkill_sysproc_names", p->comm);
		}
#endif

		if (selected[proc_type]) {
			if (oom_adj < selected_oom_adj[proc_type])
				continue;
			if (oom_adj == selected_oom_adj[proc_type] &&
			    tasksize <= selected_tasksize[proc_type])
				continue;
		}
		selected[proc_type] = p;
		selected_tasksize[proc_type] = tasksize;
		selected_oom_adj[proc_type] = oom_adj;
		lowmem_print(2, "select %d (%s), adj %d, size %d, to kill\n",
			     p->pid, p->comm, oom_adj, tasksize);
	}

	/* For each managed process type check if a process to be killed has been found:
	 * - check first if a standard killable process has been found, if so kill it
	 * - if there is no killable process, then check if a user process has been found,
	 *   if so kill it to prevent system slowdowns, hangs, etc.
	 * - if there is no killable and user process, then check if a system process has been found,
	 *   if so kill it to prevent system slowdowns, hangs, etc. */
	for (proc_type = KILLABLE_PROCESS; proc_type < MANAGED_PROCESS_TYPES; proc_type++) {
		if (selected[proc_type]) {
			lowmem_print(1, "Killing '%s' (%d), adj %d,\n" \
					"   to free %ldkB on behalf of '%s' (%d) because\n" \
					"   cache %ldkB is below limit %ldkB for oom_adj %d\n" \
					"   Free memory is %ldkB above reserved\n",
					 selected[proc_type]->comm, selected[proc_type]->pid,
					 selected_oom_adj[proc_type],
					 selected_tasksize[proc_type] * (long)(PAGE_SIZE / 1024),
					 current->comm, current->pid,
					 other_file * (long)(PAGE_SIZE / 1024),
					 minfree * (long)(PAGE_SIZE / 1024),
					 min_adj,
					 other_free * (long)(PAGE_SIZE / 1024));
			lowmem_deathpending_timeout = jiffies + HZ;
			send_sig(SIGKILL, selected[proc_type], 0);
			set_tsk_thread_flag(selected[proc_type], TIF_MEMDIE);
			rem -= selected_tasksize[proc_type];
			break;
		}
	}
	lowmem_print(4, "lowmem_shrink %lu, %x, return %d\n",
		     sc->nr_to_scan, sc->gfp_mask, rem);
	rcu_read_unlock();
	return rem;
}

static struct shrinker lowmem_shrinker = {
	.shrink = lowmem_shrink,
	.seeks = DEFAULT_SEEKS * 16
};

static int __init lowmem_init(void)
{
	task_free_register(&task_nb);
	register_shrinker(&lowmem_shrinker);
	#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES 
	init_kobject();
	#endif
	return 0;
}

static void __exit lowmem_exit(void)
{
	unregister_shrinker(&lowmem_shrinker);
	task_free_unregister(&task_nb);
}

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES                                                                            
static short lowmem_oom_adj_to_oom_score_adj(short oom_adj)                                                                                  
{                                                                                                                                            
       if (oom_adj == OOM_ADJUST_MAX)                                                                                                        
               return OOM_SCORE_ADJ_MAX;                                                                                                     
       else                                                                                                                                  
               return (oom_adj * OOM_SCORE_ADJ_MAX) / -OOM_DISABLE;                                                                          
}                                                                                                                                            
                                                                                                                                             
static void lowmem_autodetect_oom_adj_values(void)                                                                                           
{                                                                                                                                            
       int i;                                                                                                                                
       short oom_adj;                                                                                                                        
       short oom_score_adj;                                                                                                                  
       int array_size = ARRAY_SIZE(lowmem_adj);                                                                                              
                                                                                                                                                     if (lowmem_adj_size < array_size)                                                                                                     
               array_size = lowmem_adj_size;                                                                                                 
                                                                                                                                             
       if (array_size <= 0)                                                                                                                  
               return;                                                                                                                       
                                                                                                                                             
       oom_adj = lowmem_adj[array_size - 1];                                                                                                 
       if (oom_adj > OOM_ADJUST_MAX)                                                                                                         
               return;                                                                                                                       
                                                                                                                                             
       oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);                                                                             
       if (oom_score_adj <= OOM_ADJUST_MAX)                                                                                                  
               return;                                                                                                                       
                                                                                                                                             
       lowmem_print(1, "lowmem_shrink: convert oom_adj to oom_score_adj:\n");                                                                
       for (i = 0; i < array_size; i++) {                                                                                                    
               oom_adj = lowmem_adj[i];                                                                                                      
               oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);                                                                     
               lowmem_adj[i] = oom_score_adj;                                                                                                
               lowmem_print(1, "oom_adj %d => oom_score_adj %d\n",                                                                           
                            oom_adj, oom_score_adj);                                                                                         
       }                                                                                                                                     
}                                                                                                                                            
                                                                                                                                             
static int lowmem_adj_array_set(const char *val, struct kernel_param *kp)                                                              
{                                                                                                                                            
       int ret; 
       ret = param_array_set(val, kp);                                                                                                                                      
       /* HACK: Autodetect oom_adj values in lowmem_adj array */
       /* But only if not disabled via sysfs interface /sys/kernel/lowmemorykiller/auto_detect */
       /* echo 0 > /sys/kernel/lowmemorykiller/auto_detect to disable auto_detect at runtime */
       /* Default is enabled (1) when config option is enabled too */

       if (auto_detect)
       		lowmem_autodetect_oom_adj_values(); 
       return ret;
}                                                                                                                           
static int lowmem_adj_array_get(char *buffer, struct kernel_param *kp)        
{
       return param_array_get(buffer, kp);                                                                                               
}
                                                                                                                                             
static void lowmem_adj_array_free(void *arg)                                                                                                 
{
       kfree(arg);                                                                                                            
}
                                                                                                                                             
                                                                                                                                             
static const struct kparam_array __param_arr_adj = {
       .max = ARRAY_SIZE(lowmem_adj),                                                                                                        
       .num = &lowmem_adj_size,                                                                                                              
       .set = param_set_int,
       .get = param_get_int,
       .elemsize = sizeof(lowmem_adj[0]),                                                                                                    
       .elem = lowmem_adj,                                                                                                                   
};                                                                                                                                           

//For the auto_detect on/off sysfs attribute in /sys/kernel/lowmemory killer - Inspired by an0nym0us' posts on Mesa Kernel

static ssize_t ad_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", auto_detect);
}

static ssize_t ad_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	sscanf(buf, "%du", &auto_detect);
	if (auto_detect)
		printk("LMK - Auto Detect is On\n");
	else
		printk("LMK - Auto Detect is Off\n");

	return count;
}


static int init_kobject(void)
{

	int retval;
	static struct kobj_attribute ad_attribute = __ATTR(auto_detect, 0666, ad_show, ad_store); 
	static struct attribute *attrs[] = { &ad_attribute.attr, NULL, };                                                                                                                                                    
	static struct attribute_group attr_group = {
        	.attrs = attrs,                                                                                                                       
	};                                                                              
                                                                             
	static struct kobject *ad_kobj;                                                                                                      

	ad_kobj = kobject_create_and_add("lowmemorykiller", kernel_kobj);
	if (!ad_kobj) 
		return -ENOMEM;

	retval = sysfs_create_group(ad_kobj, &attr_group);
	if (retval)
		kobject_put(ad_kobj);
	return retval;
}

#endif                                                                                                                                       
                                                                                                                                             
                                                                                                                                            


module_param_named(cost, lowmem_shrinker.seeks, int, S_IRUGO | S_IWUSR);

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
__module_param_call(MODULE_PARAM_PREFIX, adj,
	lowmem_adj_array_set, lowmem_adj_array_get,
	.arr = &__param_arr_adj,
	S_IRUGO | S_IWUSR, 1);
__MODULE_PARM_TYPE(adj, "array of int");
#else
module_param_array_named(adj, lowmem_adj, int, &lowmem_adj_size,
			 S_IRUGO | S_IWUSR);
#endif

module_param_array_named(minfree, lowmem_minfree, uint, &lowmem_minfree_size,
			 S_IRUGO | S_IWUSR);
module_param_named(debug_level, lowmem_debug_level, uint, S_IRUGO | S_IWUSR);
module_param_named(lmk_fast_run, lmk_fast_run, int, S_IRUGO | S_IWUSR);
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_DO_NOT_KILL_PROCESS
module_param_named(donotkill_proc, donotkill_proc.enabled, uint, S_IRUGO | S_IWUSR);
module_param_array_named(donotkill_proc_names, donotkill_proc.names, charp,
			 &donotkill_proc.names_count, S_IRUGO | S_IWUSR);
module_param_named(donotkill_sysproc, donotkill_sysproc.enabled, uint, S_IRUGO | S_IWUSR);
module_param_array_named(donotkill_sysproc_names, donotkill_sysproc.names, charp,
			 &donotkill_sysproc.names_count, S_IRUGO | S_IWUSR);
#endif
module_init(lowmem_init);
module_exit(lowmem_exit);

MODULE_LICENSE("GPL");
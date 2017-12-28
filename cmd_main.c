#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>

#include "cmd.h"
#include "cmd_debug.h"

struct mutex mod_mutex;

static struct mutex mod_cmd_threads_mutex;
static struct list_head mod_cmd_threads_list;

struct mod_cmd_threads mod_main_cmd_threads;

int mod_threads;
static struct task_struct *mod_init_cmd_thread;

spinlock_t mod_init_lock;
wait_queue_head_t mod_init_cmd_list_waitQ;
struct list_head mod_init_cmd_list;
unsigned int mod_init_poll_cnt;

int mod_add_threads(struct mod_cmd_threads *cmd_threads, int num)
{
	int res = 0, i;
	struct mod_cmd_thread_t *thr;
	int n = 0;

	if (num == 0)
		goto out;

	spin_lock(&cmd_threads->thr_lock);
	n = cmd_threads->nr_threads;
	spin_unlock(&cmd_threads->thr_lock);

	for (i = 0; i < num; i++) {
		thr = kzalloc(sizeof(*thr), GFP_KERNEL);
		if (!thr) {
			res = -ENOMEM;
			PRINT_ERROR("Fail to allocate thr %d", res);
			goto out_wait;
		}

		thr->cmd_thread = kthread_create(mod_cmd_thread, cmd_threads, "mod%d", n++);

		if (IS_ERR(thr->cmd_thread)) {
			res = PTR_ERR(thr->cmd_thread);
			PRINT_ERROR("kthread_create() failed: %d", res);
			kfree(thr);
			goto out_wait;
		}

		spin_lock(&cmd_threads->thr_lock);
		list_add(&thr->thread_list_entry, &cmd_threads->threads_list);
		cmd_threads->nr_threads++;
		spin_unlock(&cmd_threads->thr_lock);

		wake_up_process(thr->cmd_thread);
	}

out_wait:
	if (res != 0)
		mod_del_threads(cmd_threads, i);
	
out:
	return res;
}

void mod_del_threads(struct mod_cmd_threads * cmd_threads, int num)
{
	int rc;
	for (; num != 0; num--) {
		struct mod_cmd_thread_t *ct = NULL, *ct2;

		spin_lock(&cmd_threads->thr_lock);
		list_for_each_entry_reverse(ct2, &cmd_threads->threads_list, thread_list_entry) {
			if (!ct2->being_stopped) {
				ct = ct2;
				list_del(&ct->thread_list_entry);
				ct->being_stopped = true;
				cmd_threads->nr_threads--;
				break;
			}
		}
		spin_unlock(&cmd_threads->thr_lock);

		if (!ct)
			break;

		rc = kthread_stop(ct->cmd_thread);
		if (rc != 0 && rc != -EINTR)
			PRINT_ERROR("kthread_stop() failed: %d", rc);

		kfree(ct);
	}

	return ;
}

static int mod_start_global_threads(int num)
{
	int res;

	mutex_lock(&mod_mutex);

	res = mod_add_threads(&mod_main_cmd_threads, num);
	if (res < 0)
		goto out_lock;

	mod_init_cmd_thread = kthread_run(mod_init_thread, NULL, "mod_initd");
	if (IS_ERR(mod_init_cmd_thread)) {
		res = PTR_ERR(mod_init_cmd_thread);
		PRINT_ERROR("kthread_create() for init cmd failed: %d", res);
		mod_init_cmd_thread = NULL;
	}

out_lock:
	mutex_unlock(&mod_mutex);

	return res;
}

static void mod_stop_global_threads(void)
{
	mutex_lock(&mod_mutex);

	mod_del_threads(&mod_main_cmd_threads, -1);
	if (mod_init_cmd_thread)
		kthread_stop(mod_init_cmd_thread);
	
	mutex_unlock(&mod_mutex);
	return ;
}

void mod_init_threads(struct mod_cmd_threads *cmd_threads)
{
	spin_lock_init(&cmd_threads->cmd_list_lock);
	INIT_LIST_HEAD(&cmd_threads->active_cmd_list);
	init_waitqueue_head(&cmd_threads->cmd_list_waitQ);
	INIT_LIST_HEAD(&cmd_threads->threads_list);
	spin_lock_init(&cmd_threads->thr_lock);

	mutex_lock(&mod_cmd_threads_mutex);
	list_add_tail(&cmd_threads->lists_list_entry,
		&mod_cmd_threads_list);
	mutex_unlock(&mod_cmd_threads_mutex);
	return ;
}

static int __init init_cmd(void)
{
	int res;

	mutex_init(&mod_mutex);
	spin_lock_init(&mod_init_lock);
	init_waitqueue_head(&mod_init_cmd_list_waitQ);
	INIT_LIST_HEAD(&mod_init_cmd_list);

	mutex_init(&mod_cmd_threads_mutex);
	INIT_LIST_HEAD(&mod_cmd_threads_list);

	mod_init_threads(&mod_main_cmd_threads);
	
	if (mod_threads == 0)
		mod_threads = 1;
	if (mod_threads < 1) {
		PRINT_ERROR("%s", "mod_threads can not be less than 1");
		mod_threads = 1;
	}

	res = init_vdisk();
	if (res != 0)
		goto out;

	PRINT_INFO("start global threads");
	res = mod_start_global_threads(mod_threads);
	if (res < 0) {
		PRINT_ERROR("start global threads failed! (res = %d)", res);
		goto out_thread_free;
	}
	PRINT_INFO("end global threads");

out:
	return res;

out_thread_free:
	mod_stop_global_threads();

	goto out;
}


static void __exit exit_cmd(void)
{
	mod_stop_global_threads();
	exit_vdisk();
}


module_init(init_cmd);
module_exit(exit_cmd);

MODULE_AUTHOR("Cheng Zhilong");
MODULE_LICENSE("GPL");

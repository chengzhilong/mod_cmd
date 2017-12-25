#include "cmd.h"
#include "cmd_init.h"

struct mutex mod_mutex;
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
		mod_init_cmd_threads = NULL;
		goto out_lock;
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

static int __init init_cmd(void)
{
	int res;
	if (mod_threads == 0)
		mod_threads = 1;
	if (mod_threads < 1) {
		PRINT_ERROR("%s", "mod_threads can not be less than 1");
		mod_threads = 1;
	}

	res = mod_start_global_threads(mod_threads);
	if (res < 0)
		goto out_thread_free;

out:
	return res;

out_thread_free:
	mod_stop_global_threads();

	goto out;
}


static void __exit exit_cmd(void)
{
	mod_stop_global_threads();
}


module_init(init_cmd);
module_exit(exit_cmd);

MODULE_AUTHOR("Cheng Zhilong");
MODULE_LICENSE("GPL");

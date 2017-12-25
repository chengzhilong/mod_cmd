#include "cmd.h"
#include "cmd_init.h"

/* Used for allocate space */
struct page *alloc_sys_pages(struct scatterlist *sg, gfp_t gfp_mask)
{
	struct page *page = alloc_pages(gfp_mask, 0);

	/* initialize sg */
	sg->page = page;
	sg->offset = 0;
	sg->length = PAGE_SIZE;

	return page;
}

void sgv_free_sys_sg_entries(struct scatterlist *sg, int sg_count)
{
	int i, order, pages;
	struct page *p;

	for (i = 0; i < sg_count; i++) {
		p = sg_page(&sg[i]);
		pages = PAGE_ALIGN(len) >> PAGE_SHIFT;

		while (pages > 0) {
			order = 0;

			__free_pages(p, order);

			pages -= 1 << order;
			p += 1 << order;
		}
	}
}

int alloc_sg_entries(struct scatterlist *sg, int pages, gfp_t gfp_mask)
{
	int sg_count = 0, pg;
	void *rc;

	for (pg = 0; pg < pages; pg++) {
		rc = alloc_sys_pages(&sg[sg_count], gfp_mask);
		if (rc == NULL)
			goto mem_failed;
	}
	
out:
	return sg_count;

mem_failed:
	sgv_free_sys_sg_entries(sg, sg_count);
	sg_count = 0;
	goto out;
}

void free_sg_entries(struct scatterlist * sg, int count)
{
	sgv_free_sys_sg_entries(sg, count);
	kfree(sg);

	return ;
}

struct scatterlist *sgv_pool_alloc(unsigned int size, gfp_t gfp_mask, int *count)
{
	int pages, cnt;
	struct scatterlist *res = NULL;
	struct scatterlist *sg_entries;

	int pages_to_alloc;

	if (unlikely(size == 0))
		goto out;

	pages = PAGE_ALIGN(size) >> PAGE_SHIFT;

	pages_to_alloc = pages;

	cnt = alloc_sg_entries(sg_entries, pages_to_alloc, gfp_mask);
	if (unlikely(cnt <= 0)) {
		cnt = 0;
		goto out_fail_sg_entries;
	}

	*count = cnt;
	res = sg_entries;
	sg_entries[cnt - 1].length -= PAGE_ALIGN(size) - size;

out:
	return res;

out_fail_sg_entries:
	res = NULL;
	*count = 0;
	goto out;
}


int cmd_alloc_space(struct mod_cmd *cmd)
{
	gfp_t gfp_mask;
	int res = -ENOMEM;

	gfp_mask = __GFP_NOWARN | GFP_KERNEL;

	cmd->sg = sgv_pool_alloc(cmd->bufflen, gfp_mask, &cmd->sg_cnt);
	if (unlikely(cmd->sg == NULL))
		goto out;


	if (cmd->data_direction != CMD_DATA_BIDI)
		goto success;

	cmd->out_sg = sgv_pool_alloc(cmd->out_bufflen, gfp_mask, &cmd->out_sg_cnt);
	if (unlikely(cmd->out_sg == NULL))
		goto out_sg_free;

success:
	res = 0;

out:
	return res;

out_sg_free:
	sgv_free_sys_sg_entries(cmd->sg, cmd->sg_cnt);
	cmd->sg = NULL;
	cmd->sg_cnt = 0;
	goto out;
}


void cmd_release_space(struct mod_cmd *cmd)
{
 	if (cmd->out_sg != NULL) {
		sgv_free_sys_sg_entries(cmd->out_sg, cmd->out_sg_cnt);
		cmd->out_sg = NULL;
		cmd->out_sg_cnt = 0;
		cmd->out_bufflen =0;
 	} 

	sgv_free_sys_sg_entries(cmd->sg, cmd->sg_cnt);

	cmd->sg = NULL;
	cmd->sg_cnt = 0;
	cmd->bufflen = 0;
	cmd->data_len = 0;

	return ;
}


void cmd_free_space(struct mod_cmd *cmd)
{
	cmd_release_space(cmd);

	if (cmd->cdb != cmd->cdb_buf)
		kfree(cmd->cdb);

	return ;
}


typedef int (*cmd_local_exec_fn)(struct mod_cmd *cmd);

static cmd_local_exec_fn cmd_local_fn[256] = {
	[REQUEST_SENSE] = ...,
	[REPORT_LUNS] = ...,
};


/* vdisk opcode relative */
struct vdisk_cmd_params {
	struct scatterlist small_sg[4];			//????????
	struct iovec *iv;
	int iv_count;
	struct iovec small_iv[4];
	struct mod_cmd *cmd;
	loff_t loff;
};

enum compl_status_e {
	CMD_SUCCEEDED,
	CMD_FAILED,
	RUNNING_ASYNC,
	INVALID_OPCODE,
};

typedef enum compl_status_e (*vdisk_op_fn)(struct vdisk_cmd_params *p);

static vdisk_op_fn fileio_ops[256];
static vdisk_op_fn blockio_ops[256];

static struct cmd_dev_type vdisk_file_type = {
	.name = "vdisk_fileio",
	.type = 0,
	.exec = fileio_exec,
	.on_free_cmd = fileio_on_free_cmd,
	.devt_priv = (void *)fileio_ops;
};

struct cmd_dev_type *vdisk_dev_type = &vdisk_file_type;


static struct mod_tgt_template mod_template = {
	.name = "modtgt",
	.sg_tablesize = 0,
	.use_clustering = 1,
	.max_hw_pending_time = 60,
	.xmit_response = ...,
	.rdy_to_xfer = ...,
	.on_free_cmd = ...,
};

struct mod_tgt_template *tgt_template = &mod_template;

/* ERROR Processing */
void cmd_set_busy_abnormal_status(struct mod_cmd *cmd)
{
	cmd->status = CMD_STAUS_FAILED;

	switch (cmd->state) {
		case MOD_CMD_STATE_PARSE:
		case MOD_CMD_STATE_CMD_DONE:
			res = MOD_CMD_STATE_XMIT_RESP;
			break;
		case MOD_CMD_STATE_PREPARE_SPACE:
		case MOD_CMD_STATE_RDY_TO_XFER:
		case MOD_CMD_STATE_TGT_PRE_EXEC:
		case MOD_CMD_STATE_LOCAL_EXEC:
		case MOD_CMD_STATE_REAL_EXEC:
			res = MOD_CMD_STATE_CMD_DONE;
			break;
		default:
			PRINT_ERROR("Wrong cmd state %d (cmd %p, cdb[0] %d)", cmd->state, cmd, cmd->cdb[0]);
			sBUG();
	}
}

/*************************************************************************************************************************************/
/*
 * Command Prasing
 */
#define MOD_CDB_MANDATORY		'M'		/* mandatory */
#define MOD_CDB_OPTIONAL		'O'		/* optional  */
#define MOD_CDB_VENDER			'V'		/* vendor 	 */
#define MOD_CDB_RESERVED 		'R'		/* reserved  */
#define MOD_CDB_NOTSUPP			' '		/* don't use */

struct mod_sdbops {
	uint8_t ops;
	uint8_t devkey[16];

	uint8_t info_lba_off;
	uint8_t info_lba_len;
	uint8_t info_len_off;
	uint8_t info_len_len;
	uint8_t info_data_direction;
	uint32_t info_op_flags;
	const char *info_op_name;
	int (*get_cdb_info)(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
};

static int mod_scsi_op_list[256];

#define FLAG_NONE		0

static const struct mod_sdbops mod_scsi_op_list[] = {
	
};

int mod_get_cdb_info(struct mod_cmd *cmd)
{
	int i, res = 0;
	uint8_t op;
	const struct mod_sdbops *ptr = NULL;

	op = cmd->cdb[0];
	
}

/**********************************************************************************************************************************/
/*
 * Initialize Commands' Functions
 */
static int __mod_init_cmd(struct mod_cmd *cmd)
{
	int cnt, rc;

	cmd->state = MOD_CMD_STATE_PARSE;

	rc = mod_get_cdb_info(cmd);
	if (unlikely(rc != 0)) {
		if (rc > 0) {
			PRINT_ERROR("Failed CDB(cmd %p, len %d)", cmd, cmd->cdb_len);
			goto out_err;
		}
	}
	return 0;
}


/*
 * No locks, but might be on IRQ. Returns:
 * - < 0 if the caller must not perform any further processing of @cmd;
 * - >= 0 if the caller must continue processing @cmd.
 */
static int mod_init_cmd(struct mod_cmd *cmd)
{
	int rc, res = 0;
	unsigned long flags;

	if (unlikely(!list_empty(&mod_init_cmd_list))) {
		goto out_redirect;
	}

	rc = __mod_init_cmd(mod);
	if (unlikely(rc > 0))
		goto out_redirect;
	else if (unlikely(rc != 0)) {
		res = 1;
		goto out;
	}

out:
	return res;

out_redirect:
	spin_lock_irqsave(&mod_init_lock, flags);
	list_add_tail(&cmd->cmd_list_entry, &mod_init_cmd_list);
	if (test_bit(MOD_CMD_ABORTED, &cmd->cmd_flags))
		mod_init_poll_cnt++;
	spin_unlock_irqrestore(&mod_init_lock, flags);
	wake_up(&mod_init_cmd_list_waitQ);
	res = -1;

	goto out;
}

/* Command Process Functions */
void mod_process_redirect_cmd(struct mod_cmd *cmd)
{
	unsigned long flags;

	spin_lock_irqsave(&cmd->cmd_threads->cmd_list_lock, flags);

	if (unlikely(cmd->queue_type == MOD_CMD_QUEUE_HEAD_OF_QUEUE))
		list_add(&cmd->cmd_list_entry, &cmd->cmd_threads->active_cmd_list);
	else
		list_add_tail(&cmd->cmd_list_entry, &cmd->cmd_threads->active_cmd_list);
	wake_up(&cmd->cmd_threads->cmd_list_waitQ);

	spin_unlock_irqrestore(&cmd->cmd_threads->cmd_list_lock, flags);
}

static void mod_cmd_done_local(struct mod_cmd *cmd, int next_state)
{
	cmd->state = next_state;
	mod_process_redirect_cmd(cmd);
}

int mod_prepare_space(struct mod_cmd *cmd)
{
	int res = MOD_CMD_STATE_RES_CONT_SAME, r = 0;

	if (cmd->data_direction == CMD_DATA_NONE)
		goto done;

	r = cmd_alloc_space(cmd);
	if (r != 0) {
		PRINT_ERROR("Unable to allocate or build requested buffer (size %d), sending BUSY or QUEUE FULL status",
			cmd->bufflen);
		cmd_set_busy_abnormal_status(cmd);
		goto out;
	}

done:
	if (cmd->data_direction & CMD_DATA_WRITE) {
		cmd->state = MOD_CMD_STATE_RDY_TO_XFER;
	} else {
		cmd->state = MOD_CMD_STATE_TGT_PRE_EXEC;
	}

out:
	return res;
}

int mod_rdy_to_xfer(struct mod_cmd *cmd)
{
	return 0;
}

int mod_tgt_pre_exec(struct mod_cmd *cmd)
{
	int res = MOD_CMD_STATE_RES_CONT_SAME, rc;

	cmd->mod_cmd_done = mod_cmd_done_local;

	cmd->state = MOD_CMD_STATE_LOCAL_EXEC;
	rc = mod_local_exec(cmd);
	if (rc != CMD_EXEC_NOT_COMPLETED) {
		;
	} else {
		sBUG_ON(rc != CMD_EXEC_COMPLETED);
		goto done;
	}

	cmd->state = MOD_CMD_STATE_REAL_EXEC;

	rc = mod_real_exec(cmd);
	sBUG_ON(rc != CMD_EXEC_COMPLETED);
	
done:
	return res;
}

int mod_local_exec(struct mod_cmd *cmd)
{
	int res;

	if (cmd->local_flag == 0) {
		res = CMD_EXEC_NOT_COMPLETED;
		goto out;
	}

	res = cmd_local_fn[cmd->cdb[0]](cmd);

out:
	return res;
}

int mod_real_exec(struct mod_cmd *cmd)
{
	int res = CMD_EXEC_NOT_COMPLETED;
	
	cmd->state = MOD_CMD_STATE_EXEC_WAIT;

	sBUG_ON(vdisk_dev_type != NULL);

	if (vdisk_dev_type->exec) {
		res = vdisk_dev_type->exec(cmd);

		if (res == CMD_EXEC_COMPLETED)
			goto out_complete;

		sBUG_ON(res != CMD_EXEC_NOT_COMPLETED);
	} else {
		PRINT_ERROR("vdisk_dev_type->exec is NULL!");
		// Pass Through
	}

out_complete:

	return res;
	
	
}

int mod_dev_done(struct mod_cmd *cmd)
{
	int res = MOD_CMD_STATE_RES_CONT_SAME;
	int state = MOD_CMD_STATE_XMIT_RESP, rc;

	if (likely(cmd->local_flag == 0) && likely(vdisk_dev_type->dev_done != NULL)) {
		rc = vdisk_dev_type->dev_done(cmd);
//		if (rc != MOD_CMD_STATE_DEFAULT)
//			state = rc;
	}

	return ;
}

int mod_xmit_response(struct mod_cmd *cmd)
{
	int res = MOD_CMD_STATE_RES_CONT_NEXT, rc;
	
	cmd->state = MOD_CMD_STATE_XMIT_WAIT;

	rc = tgt_template->xmit_response(cmd);

	if (likely(rc == MOD_TGT_RES_SUCCESS))
		goto out;

	cmd->state = MOD_CMD_STATE_XMIT_RESP;

	switch (rc) {
	case MOD_TGT_RES_QUEUE_FULL:
		mod_queue_retry_cmd(cmd);
		goto out;
	default:
		if (rc == MOD_TGT_RES_FATAL_ERROR) {
			PRINT_ERROR("Target driver %s xmit_response() returned fatal error", tgt_template->name);
		} else {
			PRINT_ERROR("Target driver %s xmit_response() returned invalid value %s", tgt_template->name, rc);
		}
		cmd->state = MOD_CMD_STATE_FINISH;
		res = MOD_CMD_STATE_RES_CONT_SAME;
		goto out;
	}


out:
	return res;
}

void mod_tgt_cmd_done(struct mod_cmd *cmd)
{
	sBUG_ON(cmd->state != MOD_CMD_STATE_XMIT_WAIT);

	cmd->state = MOD_CMD_STATE_FINISH;

	mod_process_redirect_cmd(cmd);
}

int mod_finish_cmd(struct mod_cmd *cmd)
{
	int res;

	if (unlikely(test_bit(MOD_CMD_ABORTED, &cmd->cmd_flags))) {
		PRINT_ERROR("cmd aborted");
	}

	if (likely(vdisk_dev_type->on_free_cmd != NULL)) {
		vdisk_dev_type->on_free_cmd(cmd);
	}

	cmd_release_space(cmd);

	if (unlikely(cmd->sense != NULL)) {
		mempool_free(cmd->sense, mod_sense_mempool);
		cmd->sense = NULL;
	}

	if (cmd->cdb != cmd->cdb_buf)
		kfree(cmd->cdb);

	if (tgt_template->on_free_cmd != NULL) 
		tgt_template->on_free_cmd(cmd);		
}


/* Called under mod_init_lock and IRQs disabled */
static void mod_do_job_init(void)
	__releases(&mod_init_lock)
	__acquires(&mod_init_lock)
{
	struct mod_cmd *cmd;

//	if (mod_init_poll_cnt > 0)
//		mod_init_poll_cnt--;

restart:
	list_for_each_entry(cmd, &mod_init_cmd_list, cmd_list_entry) {
		int rc;

		if (!test_bit(MOD_CMD_ABORTED, &cmd->cmd_flags)) {
			spin_unlock_irq(&mod_init_lock);
			rc = __mod_init_cmd(cmd);
			spin_lock_irq(&mod_init_lock);
			if (rc > 0) {
				PRINT_WARNING("%s FLAG SUSPENDED set, restarting");
				goto restart;
			}
		} else {
			PRINT_WARNING("Aborting not inited cmd %p (tag %llu)", cmd, (unsigned long long int)(cmd->tag));
			cmd_set_busy_abnormal_status(cmd);
		}

		/*
		 * Deleting cmd from cmd list after __mod_init_cmd() is necessary to keep the check
		 * in mod_init_cmd() correct to preserve the commands order.
		 */
		smp_wmb();		/* enforce the required order */
		list_del(&cmd->cmd_list_entry);
		spin_unlock(&mod_init_lock);

		spin_lock(&cmd->cmd_threads->cmd_list_lock);
		if (unlikely(cmd->queue_type == MOD_CMD_QUEUE_HEAD_OF_QUEUE))
			list_add(&cmd->cmd_list_entry, &cmd->cmd_threads->active_cmd_list);
		else
			list_add_tail(&cmd->cmd_list_entry, &cmd->cmd_threads->active_cmd_list);
		wake_up(&cmd->cmd_threads->cmd_list_waitQ);
		spin_unlock(&cmd->cmd_threads->cmd_list_lock);

		spin_lock(&mod_init_lock);

		goto restart;
	}
	return ;
}

static inline int test_init_cmd_list(void)
{
	int res = (!list_empty(&mod_init_cmd_list)) || unlikely(kthread_should_stop());
	return res;
}

int mod_init_thread(void *arg)
{
	PRINT_INFO("Init thread started");

	current->flags |= PF_NOFREEZE;
	
	set_user_nice(current, -10);

	spin_lock_irq(&mod_init_lock);
	while (!kthread_should_stop()) {
		wait_event_locked(mod_init_cmd_list_waitQ, test_init_cmd_list(), lock_irq, mod_init_lock);
		mod_do_job_init();
	}
 	spin_unlock_irq(&mod_init_lock);

	sBUG_ON(!list_empty(&mod_init_cmd_list));

	PRINT_INFO("Init thread finished");
	
	return 0;
}

void mod_process_active_cmd(struct mod_cmd *cmd)
{
	int res;

	do {
		switch (cmd->state) {
			case MOD_CMD_STATE_PREPARE_SPACE:
				res = mod_prepare_space(cmd);
				break;
			case MOD_CMD_STATE_RDY_TO_XFER:
				res = mod_rdy_to_xfer(cmd);
				break;
			case MOD_CMD_STATE_TGT_PRE_EXEC:
				res = mod_tgt_pre_exec(cmd);
			case MOD_CMD_STATE_LOCAL_EXEC:
				res = mod_local_exec(cmd);
				break;
			case MOD_CMD_STATE_REAL_EXEC:
				res = mod_real_exec(cmd);
				break;
			case MOD_CMD_STATE_CMD_DONE:
				res = mod_dev_done(cmd);
			case MOD_CMD_STATE_XMIT_RESP:
				res = mod_xmit_response(cmd);
			case MOD_CMD_STATE_FINISH:
				res = mod_finish_cmd(cmd);
			default:
				PRINT_ERROR("cmd (%p) in state %d, but shouldn't be", cmd, cmd->state);
				sBUG();
				break;
		}
	} while (res == MOD_CMD_STATE_RES_CONT_SAME);

	if (res == MOD_CMD_STATE_RES_CONT_NEXT) {
		;
	} else {
		sBUG();
	}

	return ;
}

/* 
 * Called under cmd_list_lock and IRQs disabled
 */
static void mod_do_job_active(struct list_head *cmd_list, spinlock_t *cmd_list_lock)
	__releases(cmd_list_lock)
	__acquires(cmd_list_lock)
{
	while (!list_empty(cmd_list)) {
		struct mod_cmd *cmd = list_first_entry(cmd_list, typeof(*cmd), cmd_list_entry);
		list_del(&cmd->cmd_list_entry);

		spin_unlock_irq(cmd_list_lock);
		mod_process_active_cmd(cmd);
		spin_lock_irq(cmd_list_lock);
	}
}

static inline int test_cmd_threads(struct mod_cmd_threads *p_cmd_threads)
{
	int res = !list_empty(&p_cmd_threads->active_cmd_list) || unlikely(kthread_should_stop());
	return res;
}

int mod_cmd_thread(void *arg)
{
	struct mod_cmd_threads *p_cmd_threads = arg;

	current->flags |= PF_NOFREEZE;

	spin_lock_irq(&p_cmd_threads->cmd_list_lock);
	while (!kthread_should_stop()) {
		wait_event_locked(p_cmd_threads->cmd_list_waitQ, test_cmd_threads(p_cmd_threads), lock_irq, p_cmd_threads->cmd_list_lock);

		mod_do_job_active(&p_cmd_threads->active_cmd_list, &p_cmd_threads->cmd_list_lock);
	}
	spin_unlock_irq(&p_cmd_threads->cmd_list_lock);

	return 0;
}

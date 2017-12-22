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



/* ERROR Processing */
void cmd_set_busy_abnormal_status(struct mod_cmd *cmd)
{
	cmd->status = CMD_STAUS_FAILED;

	switch (cmd->state) {
		case MOD_CMD_STATE_INIT:
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


/* Command Process Functions */

static void mod_cmd_done_local(struct mod_cmd *cmd, int next_state)
{

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

	
}

int mod_cmd_done(struct mod_cmd *cmd)
{
	return 0;
}

int mod_xmit_response(struct mod_cmd *cmd)
{
	return 0;
}

int mod_finish_cmd(struct mod_cmd *cmd)
{

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
				res = mod_cmd_done(cmd);
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

#ifndef CMD_H_
#define CMD_H_

#define CMD_STATUS_OK			0
#define CMD_STAUS_FAILED		1
#define CMD_STATUS_ERROR		2
#define CMD_STATUS_ABORT		3

#define MOD_TGT_RES_SUCCESS		0
#define MOD_TGT_RES_QUEUE_FULL 	-1
#define MOD_TGT_RES_FATAL_ERROR -2


#define CMD_EXEC_COMPLETED		0
#define CMD_EXEC_NOT_COMPLETED	1


/* Cmd's async (atomic) flags */
#define MOD_CMD_ABORTED			0
#define MOD_CMD_NO_RESP			1

enum mod_cmd_queue_type {
	MOD_CMD_QUEUE_UNTAGGED = 0,
	MOD_CMD_QUEUE_SIMPLE,
	MOD_CMD_QUEUE_ORDERED,
	MOD_CMD_QUEUE_HEAD_OF_QUEUE,
	MOD_CMD_QUEUE_ACA
};


#define MAX_CDB_SIZE			16		/* Max Size of CDB */


#define MOD_MAX_NAME			50		/* Max size of various names */

//#define PAGE_SIZE				4096		/* defined by kernel header file*/

/* States of command processing state machine */
enum {
	MOD_CMD_STATE_PARSE,
	MOD_CMD_STATE_PREPARE_SPACE,
	MOD_CMD_STATE_RDY_TO_XFER,
	MOD_CMD_STATE_TGT_PRE_EXEC,
	MOD_CMD_STATE_LOCAL_EXEC,
	MOD_CMD_STATE_REAL_EXEC,
	MOD_CMD_STATE_EXEC_WAIT,
	MOD_CMD_STATE_CMD_DONE,
	MOD_CMD_STATE_XMIT_RESP,
	MOD_CMD_STATE_FINISH,
	MOD_CMD_STATE_XMIT_WAIT
};

/*
 * Can be returned insteadof cmd's state by dev handler's functions, if the command's
 * state should be set by default
 */
#define MOD_CMD_STATE_DEFAULT			500

#define MOD_CMD_STATE_RES_CONT_NEXT		0
#define MOD_CMD_STATE_RES_CONT_SAME		(MOD_CMD_STATE_RES_CONT_NEXT + 1)

#define CMD_DATA_UNKNOWN			0
#define CMD_DATA_READ 				1
#define CMD_DATA_WRITE 				2
#define CMD_DATA_BIDI 		 		(CMD_DATA_READ | CMD_DATA_WRITE)
#define CMD_DATA_NONE  				4

typedef enum dma_data_direction cmd_data_direction;

struct mod_cmd_thread_t {
	struct task_struct *cmd_thread;
	struct list_head thread_list_entry;
	bool being_stopped;
};


/*
 * Structure to control commands' queuing and threads pool processing the queue
 */
struct mod_cmd_threads {
	spinlock_t cmd_list_lock;
	struct list_head active_cmd_list;
	wait_queue_head_t cmd_list_waitQ;

	spinlock_t thr_lock;					/* Protects nr_threads and threads_list */
	int nr_threads;							/* number of processing threads */
	struct list_head threads_list;			/* processing threads */

	struct list_head lists_list_entry;
};

struct mod_cmd {
	struct list_head cmd_list_entry;
	struct mod_cmd_threads *cmd_threads;

	atomic_t cmd_ref;

	int state;
	uint8_t status;							/* status byte from target device */
	

	unsigned long cmd_flags;				/* cmd's async flags */
	uint64_t tag;							/* Used to found the cmd by function... */

	uint64_t lun;

	/* Command Relative*/
	uint8_t *cdb;
	unsigned short cdb_len;
	uint8_t cdb_buf[MAX_CDB_SIZE];

	uint8_t local_flag;		/* various flags of this opcode: Local cmd 0, or 1 */

	enum mod_cmd_queue_type queue_type;

	cmd_data_direction data_direction;

	/* Read/Write Operation Relative */
	int64_t lba;			/* LBA of this cmd */
	int64_t data_len;		/* Cmd Data Length */

	/* Completion routine */
	void (*mod_cmd_done)(struct mod_cmd *cmd, int next_state);

	int bufflen;			/* cmd buffer length */
	int sg_cnt;				/* SG segments count */
	struct scatterlist *sg;	/* cmd data buffer SG vector */


	/* Bidirectional transfers support */
	int out_bufflen;					/* WRITE buffer length */
	struct scatterlist *out_sg;			/* WRITE data buffer SG vector */
	int out_sg_cnt;						/* WRITE SG segments count */
			
	uint8_t *sense;
	unsigned short sense_valid_len;
	unsigned short sense_buflen;
	
};


struct cmd_device {
	unsigned int type;					/* SCSI type of the device */

	uint32_t block_size;
	uint64_t nblocks;
	int block_shift;
	
	int id;								/* virtual device internal ID */
	char *name;							/* Pointer to virtual device name, for convenience only */
	struct list_head dev_list_entry;	/* list entry in global devices list */
	
};

struct cmd_dev_type {
	int type;
	
	int (*exec)(struct mod_cmd *cmd);

	int (*dev_done)(struct mod_cmd *cmd);

	void (*on_free_cmd)(struct mod_cmd *cmd);

	char name[MOD_MAX_NAME + 10];

	void *devt_priv;			/* Pointer to parent dev type in the sysfs hierarchy */
};

/*
 * MOD_CMD target template: defines target driver's parameters and callback functions.
 */
struct mod_tgt_template {
	int sg_tablesize;			/* SG tablesize allows to check scatter/gather can be used or not. */
	int max_hw_pending_time;	/* The maximum time in seconds cmd can stay inside the target hardware. */
	unsigned use_clustering:1;	/* True, if this target adapter can benefit from using SG-vectr clustering(i.e. smaller number of segments) */
	int (*xmit_response)(struct mod_cmd *cmd);
	int (*rdy_to_xfer)(struct mod_cmd *cmd);
	void (*on_free_cmd)(struct mod_cmd *cmd);

	const char name[MOD_MAX_NAME];		/* Name of the template. Must be unique to identify the template. */
};


/* Allocate/Free Space */

//struct kmem_cache *sg_
struct page *alloc_sys_pages(struct scatterlist *sg, gfp_t gfp_mask);
void sgv_free_sys_sg_entries(struct scatterlist *sg, int sg_count);

int alloc_sg_entries(struct scatterlist *sg, int pages, gfp_t gfp_mask);
void free_sg_entries(struct scatterlist *sg, int count);


void mod_process_active_cmd(struct mod_cmd *cmd);

static inline void prepare_to_wait_exclusive_head(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	unsigned long flags;

	wait->flags |= WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);

	if (list_empty(&wait->task_list))
		__add_wait_queue(q, wait);
	set_current_state(state);
	
	spin_unlock_irqrestore(&q->lock, flags);
}

#define wait_event_locked(wq, condition, lock_type, lock)			\
	if (!(condition)) {						\
		DEFINE_WAIT(__wait);				\
											\
		do {								\
			prepare_to_wait_exclusive_head(&(wq), &__wait, TASK_INTERRUPTIBLE);		\
			if (condition)					\
				break;						\
			spin_un ## lock_type(&(lock));							\
			schedule();						\
			spin_ ## lock_type(&(lock));	\
		} while (!(condition));				\
		finish_wait(&(wq), &__wait);		\
	}


int mod_init_thread(void *arg);
extern int mod_cmd_thread(void *arg);

extern int mod_add_threads(struct mod_cmd_threads *cmd_threads, int num);
extern void mod_del_threads(struct mod_cmd_threads *cmd_threads, int num);

#endif

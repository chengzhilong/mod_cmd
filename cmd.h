#ifndef CMD_H_
#define CMD_H_

#define CMD_STATUS_OK			0
#define CMD_STAUS_FAILED		1
#define CMD_STATUS_ERROR		2
#define CMD_STATUS_ABORT		3


#define CMD_EXEC_COMPLETED		0
#define CMD_EXEC_NOT_COMPLETED	1


#define MAX_CDB_SIZE			16		/* Max Size of CDB */


#define MOD_MAX_NAME			50		/* Max size of various names */

//#define PAGE_SIZE				4096		/* defined by kernel header file*/

/* States of command processing state machine */
enum {
	MOD_CMD_STATE_INIT,
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

#define MOD_CMD_STATE_RES_CONT_NEXT		0
#define MOD_CMD_STATE_RES_CONT_SAME		(MOD_CMD_STATE_RES_CONT_NEXT + 1)

#define CMD_DATA_UNKNOWN			0
#define CMD_DATA_READ 				1
#define CMD_DATA_WRITE 				2
#define CMD_DATA_BIDI 		 		(CMD_DATA_READ | CMD_DATA_WRITE)
#define CMD_DATA_NONE  				4

typedef enum dma_data_direction cmd_data_direction;

struct mod_cmd {
	struct list_head cmd_list_entry;

	atomic_t cmd_ref;

	int state;
	uint8_t status;			/* status byte from target device */
	

	uint64_t tag;			/* Used to found the cmd by function... */

	uint64_t lun;

	/* Command Relative*/
	uint8_t *cdb;
	unsigned short cdb_len;
	uint8_t cdb_buf[MAX_CDB_SIZE];

	uint8_t local_flag;		/* various flags of this opcode: Local cmd 0, or 1 */

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
	
	int id;						/* virtual device internal ID */
	char *name;					/* Pointer to virtual device name, for convenience only */
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


/* Allocate/Free Space */

//struct kmem_cache *sg_
struct page *alloc_sys_pages(struct scatterlist *sg, gfp_t gfp_mask);
void sgv_free_sys_sg_entries(struct scatterlist *sg, int sg_count);

int alloc_sg_entries(struct scatterlist *sg, int pages, gfp_t gfp_mask);
void free_sg_entries(struct scatterlist *sg, int count);


void mod_process_active_cmd(struct mod_cmd *cmd);

#endif
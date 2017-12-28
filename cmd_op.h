#ifndef CMD_OP_H_
#define CMD_OP_H_

#include "cmd.h"
#include "cmd_debug.h"

extern struct mod_cmd_threads mod_main_cmd_threads;
extern spinlock_t mod_init_lock;
extern wait_queue_head_t mod_init_cmd_list_waitQ;
extern struct list_head mod_init_cmd_list;
extern unsigned int mod_init_poll_cnt;

enum compl_status_e {
	CMD_SUCCEEDED,
	CMD_FAILED,
	RUNNING_ASYNC,
	INVALID_OPCODE,
};

typedef int (*cmd_local_exec_fn)(struct mod_cmd *cmd);

/* vdisk opcode relative */
struct vdisk_cmd_params {
	struct scatterlist small_sg[4];			//????????
	struct iovec *iv;
	int iv_count;
	struct iovec small_iv[4];
	struct mod_cmd *cmd;
	loff_t loff;
};

typedef enum compl_status_e (*vdisk_op_fn)(struct vdisk_cmd_params *p);

/*
 *  Function Declaration
 */
static int vdisk_parse(struct mod_cmd *cmd);
static int fileio_exec(struct mod_cmd *cmd);
static void fileio_on_free_cmd(struct mod_cmd *cmd);

int ag_rdy_to_xfer(struct mod_cmd * cmd);
int ag_xmit_response(struct mod_cmd *cmd);
void ag_on_free_cmd(struct mod_cmd *cmd);

static int mod_report_luns_local(struct mod_cmd *cmd);
static int mod_request_sense_local(struct mod_cmd *cmd);

static enum compl_status_e vdisk_synchronize_cache(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_mode_sense(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_read_capacity(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_exec_inquiry(struct vdisk_cmd_params *p);
static enum compl_status_e vdisk_nop(struct vdisk_cmd_params* p);

static enum compl_status_e fileio_exec_read(struct vdisk_cmd_params *p);
static enum compl_status_e fileio_exec_write(struct vdisk_cmd_params *p);
static enum compl_status_e vdev_exec_verify(struct vdisk_cmd_params *p);
static enum compl_status_e fileio_exec_write_verify(struct vdisk_cmd_params *p);

int cmd_set_busy_abnormal_status(struct mod_cmd *cmd);


/*
 * Command Prasing
 */
#define MOD_CDB_MANDATORY		'M'		/* mandatory */
#define MOD_CDB_OPTIONAL		'O'		/* optional  */
#define MOD_CDB_VENDER			'V'		/* vendor 	 */
#define MOD_CDB_RESERVED 		'R'		/* reserved  */
#define MOD_CDB_NOTSUPP			' '		/* don't use */

struct mod_sdbops {
	uint8_t ops;		/* SCSI-2 op codes */
	uint8_t devkey[16];	/* Key for every device type M,O,V,R
				 * type_disk      devkey[0]
				 * type_tape      devkey[1]
				 * type_printer   devkey[2]
				 * type_processor devkey[3]
				 * type_worm      devkey[4]
				 * type_cdrom     devkey[5]
				 * type_scanner   devkey[6]
				 * type_mod       devkey[7]
				 * type_changer   devkey[8]
				 * type_commdev   devkey[9]
				 * type_reserv    devkey[A]
				 * type_reserv    devkey[B]
				 * type_raid      devkey[C]
				 * type_enclosure devkey[D]
				 * type_reserv    devkey[E]
				 * type_reserv    devkey[F]
				 */
	uint8_t info_lba_off;	/* LBA offset in cdb */
	uint8_t info_lba_len;	/* LBA length in cdb */
	uint8_t info_len_off;	/* length offset in cdb */
	uint8_t info_len_len;	/* length length in cdb */
	uint8_t info_data_direction; /* init --> target: CMD_DATA_WRITE
				   * target --> init: SCST_DATA_READ
				   * target <--> init: SCST_DATA_READ|CMD_DATA_WRITE
				   */
	uint32_t info_op_flag;	/* various flags of this opcode */
	const char *info_op_name;/* op code SCSI full name */
	int (*get_cdb_info)(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
};


static int get_cdb_info_none(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_len_1(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static inline int get_cdb_info_lba_3_len_1_256(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_lba_3_len_1_256_read(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_lba_3_len_1_256_write(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_len_2(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_read_capacity(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_lba_4_len_2(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int scst_parse_rdprotect(struct mod_cmd *cmd);
static int get_cdb_info_read_10(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_lba_4_len_2_wrprotect(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_verify10(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_lba_4_none(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_lba_8_none(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);
static int get_cdb_info_len_4(struct mod_cmd *cmd, const struct mod_sdbops *sdbops);


int mod_rdy_to_xfer(struct mod_cmd *cmd);
int mod_tgt_pre_exec(struct mod_cmd *cmd);
int mod_local_exec(struct mod_cmd *cmd);
int mod_real_exec(struct mod_cmd *cmd);


#endif

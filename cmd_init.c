#include "cmd.h"
#include "cmd_init.h"

static int __init init_cmd(void)
{

	return 0;
}


static void __exit exit_cmd(void)
{
	
}


module_init(init_cmd);
module_exit(exit_cmd);

MODULE_AUTHOR("Cheng Zhilong");
MODULE_LICENSE("GPL");

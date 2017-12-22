#ifndef CMD_DEBUG_H_
#define CMD_DEBUG_H_

#define sBUG() 		BUG()
#define sBUG_ON(p)	BUG_ON(p)

#define PRINT(format, args...)			printk(format "\n", ## args)
#define PRINTN(format, args...)			printk(format, ## args)

#define PRINT_WARNING(format, args...)	PRINT("%s: *** ERROR ***: " format, __FUNCTION__, __LINE__, ## args)
#define PRINT_ERROR(format, args...)	PRINT("%s: *** ERROR ***: " format, __FUNCTION__, __LINE__, ## args)
		
#endif
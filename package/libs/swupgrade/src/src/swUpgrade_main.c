#include "../driver_api/sw_upgrade.h"

int main()
{
	revanche_u8_t error_code;
        int mOption=0;
        uint32_t pri_bt_cnt, sec_bt_cnt;
        uint32_t pri_bt_cnt_wr, sec_bt_cnt_wr;
        uint32_t active_partition;

	do{
		printf("\n=======Bootconfig application=======");
		printf("\n 1. Get boot count.");
		printf("\n 2. Write primary boot count.");
		printf("\n 3. Write secondary boot count.");
		printf("\n 4. Get active partition");
		printf("\n 5. Update boot count");
		printf("\n 6. dump crashlog ");
		printf("\n 7. Exit");
		printf("\n====================================");
		printf("\n Please select the option:");
		fflush(stdout);
		scanf("%d",&mOption);

		if(mOption==7)
			break;

		getchar();

		switch (mOption)
		{
			case 1:
				if(revanche_ctrl_read_boot_count(&pri_bt_cnt, &sec_bt_cnt,(revanche_inf_ecode_et *) &error_code)==REVANCHE_IRET_SUCCESS){
					printf("\nPrimary boot count:%d",pri_bt_cnt);
					printf("\nSecondary boot count:%d",sec_bt_cnt);
                                }
                                else {
					printf("\nFailed to get boot count");
                                }
                                break;
			case 2:
				printf("\nEnter primary boot count:");
				fflush(stdout);
				scanf("%d", &pri_bt_cnt_wr);

				if(revanche_ctrl_write_boot_count(pri_bt_cnt_wr, 0, (revanche_inf_ecode_et *)&error_code)==REVANCHE_IRET_SUCCESS){
					printf("\nBoot Count Write Ok");
                                }
                                else {
					printf("\nBoot Count Write Failed");
                                }
				break;
			case 3:
				printf("\nEnter secondary boot count:");
				fflush(stdout);
				scanf("%d", &sec_bt_cnt_wr);

				if(revanche_ctrl_write_boot_count(sec_bt_cnt_wr, 1, (revanche_inf_ecode_et *)&error_code)==REVANCHE_IRET_SUCCESS){
					printf("\nBoot Count Write Ok");
                                }
                                else {
					printf("\nBoot Count Write Failed");
                                }
				break;
			case 4:
				if(revanche_ctrl_read_active_partition(&active_partition, (revanche_inf_ecode_et *)&error_code)==REVANCHE_IRET_SUCCESS){
					printf("\nActive partition:%d",active_partition);
                                }
                                else {
					printf("\nFailed to get active partition");
                                }
				break;
			case 5:
				if(revanche_update_boot_count((revanche_inf_ecode_et *)&error_code)==REVANCHE_IRET_SUCCESS){
					printf("\nBoot Count Write OK");
                                }
                                else {
					printf("\nBoot Count Write Failed");
                                }
				break;
            case 6:
            {
                 char buf[BUF_SIZE];

                 if(revanche_read_crashlog(&buf[0]) == REVANCHE_IRET_SUCCESS)
                    printf("\n read ok\n");
                 else
                    printf("\n read failed\n");
                 break;
            }
			default:
				printf("\nInvalid selection");
				break;
		}

		}while(mOption!=39);
		printf("\n\n");

	return 0;
}

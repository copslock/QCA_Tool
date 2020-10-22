#ifndef REVANCHE_ENUM_COMMON_H
#define REVANCHE_ENUM_COMMON_H
/*****************************************************************************
*  FILE NAME             : revanche_enums_common.h
*  PRINCIPAL AUTHOR      : Revanche team
*  SUBSYSTEM NAME        :
*  MODULE NAME           :
*  LANGUAGE              : C
*  DATE OF FIRST RELEASE :
*  AUTHOR                :
*  FUNCTIONS DEFINED(Applicable for Source files) :
*  DESCRIPTION           :
*
******************************************************************************/
typedef enum{
     REVANCHE_IRET_FAILURE = 0,
     REVANCHE_IRET_SUCCESS
}revanche_inf_return_et;

typedef enum {
     REVANCHE_IECODE_NO_ERR = 1,
     REVANCHE_IECODE_READ_TIMEOUT = 2,
     REVANCHE_IECODE_PERMS_ERR = 3,
     REVANCHE_IECODE_INVALID_PARAM = 4,
     REVANCHE_IECODE_NO_MEMORY = 5,
     REVANCHE_IECODE_WRITE_ERR = 6,
     REVANCHE_IECODE_ERR_OPEN_DEVFILE = 7,
     REVANCHE_IECODE_ERR_CLOSE_DEVFILE = 8,
     REVANCHE_IECODE_READ_ERR = 9,
     REVANCHE_IECODE_MAGIC_ERR = 10
}revanche_inf_ecode_et;

typedef enum {
        BSP_REVANCHE_MTD_ERROR = -1,
        BSP_REVANCHE_MTD_SUCCESS,
}bsp_revanche_status;
#endif



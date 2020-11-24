#ifndef _RPP_UTIL_H_
#define _RPP_UTIL_H_

#include "rpp_header.h"

int util_install_certificate(const uint32_t phyhandle,
                             const char* sta,
                             const char* key_filename,
                             const char* cert_filename);

int util_uninstall_certificate(const uint32_t phyhandle);

int util_install_certificate2(const uint32_t phyhandle,
                              uint32_t stanum,
                              const char* keyname,
                              const char* filepath);

int util_is_empty_array(uint8_t* array, size_t size);

char* util_mac_addr_to_str(uint8_t* addr);

uint8_t util_str_to_mac_addr(const char* str, uint8_t* macValue);

uint8_t util_is_intf_online(const char* intfName);

uint8_t util_is_mcs12_13_support(const char* infName, uint8_t staNum);

#endif /* _RPP_UTIL_H_ */

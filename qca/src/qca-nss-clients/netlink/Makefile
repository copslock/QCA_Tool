ccflags-y := -Werror
ccflags-y += -I$(obj)/include
ccflags-y += -I$(obj)/../exports
ccflags-y += -DNSS_NL_DEBUG_LEVEL=4
ccflags-y += -DNSS_CLIENT_BUILD_ID="$(BUILD_ID)"

ccflags-y += -DCONFIG_NSS_NLIPV4=1
ccflags-y += -DCONFIG_NSS_NLIPV6=1
ccflags-y += -DCONFIG_NSS_NLIPSEC=1
ccflags-y += -DCONFIG_NSS_NLOAM=1
ccflags-y += -DCONFIG_NSS_NLGRE_REDIR_FAMILY=1
ccflags-y += -DCONFIG_NSS_NLETHRX=1
ccflags-y += -DCONFIG_NSS_NLEDMA=1
ccflags-y += -DCONFIG_NSS_NLDYNAMIC_INTERFACE=1
ccflags-y += -DCONFIG_NSS_NLN2H=1
ccflags-y += -DCONFIG_NSS_NLC2C_TX=1
ccflags-y += -DCONFIG_NSS_NLC2C_RX=1
ccflags-y += -DCONFIG_NSS_NLIPV4_REASM=1
ccflags-y += -DCONFIG_NSS_NLIPV6_REASM=1
ccflags-y += -DCONFIG_NSS_NLWIFILI=1
ccflags-y += -DCONFIG_NSS_NLLSO_RX=1
ccflags-y += -DCONFIG_NSS_NLMAP_T=1
ccflags-y += -DCONFIG_NSS_NLPPPOE=1
ccflags-y += -DCONFIG_NSS_NLL2TPV2=1
ccflags-y += -DCONFIG_NSS_NLPPTP=1

qca-nss-netlink-objs := nss_nl.o
qca-nss-netlink-objs += nss_nlgre_redir_family.o
qca-nss-netlink-objs += nss_nlgre_redir_cmd.o
qca-nss-netlink-objs += nss_nlgre_redir_cmn.o
qca-nss-netlink-objs += nss_nlgre_redir.o
qca-nss-netlink-objs += nss_nlgre_redir_lag.o
qca-nss-netlink-objs += nss_nlipv4.o
qca-nss-netlink-objs += nss_nlipv6.o
qca-nss-netlink-objs += nss_nloam.o
qca-nss-netlink-objs += nss_nlethrx.o
qca-nss-netlink-objs += nss_nledma.o
qca-nss-netlink-objs += nss_nldynamic_interface.o
qca-nss-netlink-objs += nss_nln2h.o
qca-nss-netlink-objs += nss_nlc2c_tx.o
qca-nss-netlink-objs += nss_nlc2c_rx.o
qca-nss-netlink-objs += nss_nlipv4_reasm.o
qca-nss-netlink-objs += nss_nlipv6_reasm.o
qca-nss-netlink-objs += nss_nlwifili.o
qca-nss-netlink-objs += nss_nllso_rx.o
qca-nss-netlink-objs += nss_nlmap_t.o
qca-nss-netlink-objs += nss_nlpppoe.o
qca-nss-netlink-objs += nss_nll2tpv2.o
qca-nss-netlink-objs += nss_nlpptp.o

CAPWAP_ENABLED:=CONFIG_PACKAGE_kmod-qca-nss-drv-capwapmgr=y
CAPWAP_CONFIG:=$(shell  grep $(CAPWAP_ENABLED) $(TOPDIR)/.config)
ifeq ($(CAPWAP_CONFIG),$(CAPWAP_ENABLED))
ccflags-y += -DCONFIG_NSS_NLCAPWAP=1
qca-nss-netlink-objs += nss_nlcapwap.o
else
ccflags-y += -DCONFIG_NSS_NLCAPWAP=0
endif
DTLS_ENABLED:=CONFIG_PACKAGE_kmod-qca-nss-drv-dtlsmgr=y
DTLS_CONFIG:=$(shell  grep $(DTLS_ENABLED) $(TOPDIR)/.config)
ifeq ($(DTLS_CONFIG),$(DTLS_ENABLED))
ccflags-y += -DCONFIG_NSS_NLDTLS=1
qca-nss-netlink-objs += nss_nldtls.o
else
ccflags-y += -DCONFIG_NSS_NLDTLS=0
endif
IPSEC_ENABLED:=CONFIG_PACKAGE_kmod-qca-nss-drv-ipsecmgr=y
IPSEC_CONFIG:=$(shell  grep $(IPSEC_ENABLED) $(TOPDIR)/.config)
ifeq ($(IPSEC_CONFIG),$(IPSEC_ENABLED))
qca-nss-netlink-objs += nss_nlipsec.o
endif
obj-m += qca-nss-netlink.o

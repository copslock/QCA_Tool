
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-wifi-hk-fw
PKG_VERSION:=WLAN.HK.2.3.r2-00064-QCAHKSWPL_SILICONZ-3
PKG_RELEASE:=1
PKG_LABEL:=$(shell echo $(PKG_VERSION) | cut -d'-' -f2)
PKG_SPIN:=$(shell echo $(PKG_VERSION) | cut -d'-' -f4)

PKG_SOURCE:=qca-wifi-fw-QCA8074_v1.0-$(PKG_VERSION).tar.bz2
PKG_SOURCE_V2:=qca-wifi-fw-QCA8074_v2.0-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://vm-cnsswebserv/cnss_win/santaclara/dev01/WLAN.HK.2.3/$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_MD5SUM:=skip

include $(INCLUDE_DIR)/package.mk

PKG_CMN_NAME:=fwcommon
PKG_CMN_SOURCE:=qca-wifi-fw-src-component-cmn-$(PKG_VERSION).tgz

define Download/fwcommon
  FILE:=$(PKG_CMN_SOURCE)
  VERSION:=$(PKG_VERSION)
  URL:=$(PKG_SOURCE_URL)
  MD5SUM:=skip
endef
$(eval $(call Download,fwcommon))

PKG_FW_CMN:=qca-wifi-fw-src-component-cmn-$(PKG_VERSION).tgz

define Build/Prepare
	$(TAR) xzvf $(TOPDIR)/dl/$(PKG_FW_CMN) -C $(TOPDIR)/dl
endef


define WifiFirmware
  define Package/$(PKG_NAME)$(1)
    SECTION:=QCA
    CATEGORY:=QCA Proprietary software
    URL:=http://www.qca.qualcomm.com
    MAINTAINER:=Qualcomm Atheros
    TITLE:=QCA Wifi Firmware$(1)
    DEPENDS:=@!TARGET_ipq_ipq60xx @!TARGET_ipq_ipq60xx_64
    VARIANT:=$(2)
    PKGARCH:=all
  endef

  define Package/$(PKG_NAME)$(1)/description
    This package contains the qca-wifi firmware($(1)) used in 10.x drivers
  endef

  define Package/$(PKG_NAME)-hw1-10.4-asic/install
#	true
	$(INSTALL_DIR) $$(1)/lib/firmware/IPQ8074
	$(HOST_TAR) jxvf $(DL_DIR)/$(PKG_SOURCE_V2) -C $(PKG_BUILD_DIR) --strip-components=1
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/PIL_IMAGES/* $$(1)/lib/firmware/IPQ8074/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bdwlan* $$(1)/lib/firmware/IPQ8074/
	$(INSTALL_DIR) $$(1)/vendor/firmware
#	$(INSTALL_DATA) $(PKG_BUILD_DIR)/Data.msc $$(1)/vendor/firmware/
	$(CP) ./files/lib/firmware/IPQ8074/* $$(1)/lib/firmware/IPQ8074/
	$(INSTALL_DIR) $$(1)/lib/firmware/qcn9000
	$(CP) ./files/lib/firmware/qcn9000/* $$(1)/lib/firmware/qcn9000/
	$(CP) ./files/lib/firmware/qcn9000/firmware_rdp_feature.ini $$(1)/lib/firmware/
#	$(CP) ./files/vendor/firmware/Data.msc $$(1)/vendor/firmware/
	$(INSTALL_DIR) $$(1)/etc/init.d
	# $(INSTALL_BIN) ./files/etc/init.d/wifi_fw_mount $$(1)/etc/init.d
  endef

  $$(eval $$(call BuildPackage,$(PKG_NAME)$(1)))
endef

Build/Compile=true

$(eval $(call WifiFirmware,-hw1-10.4-asic,-QCAHK_hw_1,QCA8074))

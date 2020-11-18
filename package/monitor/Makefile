# OpenWrt Makefile for rppslave program

# Add the below commented line in .config file
# rppslave
#
#CONFIG_PACKAGE_monitor=y
#

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=monitor
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/monitor
	SECTION:=monitor
	CATEGORY:=monitor
    DEPENDS:=+libpthread +librt +libm +libpcap
	TITLE:=monitor
	Package/PKG_NAME/description:=\
    monitor mode implementation 
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/monitor/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/monitord $(1)/usr/bin/
endef

$(eval $(call BuildPackage,monitor))

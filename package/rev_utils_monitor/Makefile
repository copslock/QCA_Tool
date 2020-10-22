# OpenWrt Makefile for rev_utils_monitor program

# Add the below commented line in .config file
#
#CONFIG_PACKAGE_rev_utils_monitor=y
#

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=rev_utils_monitor
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/rev_utils_monitor
	SECTION:=rev_utils_monitor
	CATEGORY:=rev_utils_monitor
    DEPENDS:=+libpthread +librt +libm +libpcap
	TITLE:=rev_utils_monitor
	Package/PKG_NAME/description:=\
    rev_utils_monitor implementation 
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/rev_utils_monitor/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rev_utils_monitor $(1)/usr/bin/
endef

$(eval $(call BuildPackage,rev_utils_monitor))

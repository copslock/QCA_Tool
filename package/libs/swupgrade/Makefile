# OpenWrt Makefile for swupgrade program

# Add the below commented line in .config file
# swupgrade
#
#CONFIG_PACKAGE_swupgrade=y
#

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=swupgrade
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/swupgrade
        SECTION:=libs
        CATEGORY:=Libraries
        TITLE:=Lib for updating bootcount
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/swupgrade/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/img_upgrade $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rev_crashdump $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libswupgrade.so $(1)/lib/
endef

$(eval $(call BuildPackage,swupgrade))

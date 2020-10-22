# OpenWrt Makefile for revanche_upgrade program

# Add the below commented line in .config file
#
#CONFIG_PACKAGE_revanche_upgrade=y
#

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=revanche_upgrade
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/revanche_upgrade
	SECTION:=revanche_upgrade
	CATEGORY:=revanche_upgrade
    DEPENDS:=+libpthread +librt +libm +libpcap +pcie_fpga_util
	TITLE:=revanche_upgrade
	Package/PKG_NAME/description:=\
    revanche_upgrade implementation
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/revanche_upgrade/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/revanche_upgrade $(1)/usr/bin/
endef

$(eval $(call BuildPackage,revanche_upgrade))

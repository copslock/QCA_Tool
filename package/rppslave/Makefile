# OpenWrt Makefile for rppslave program

# Add the below commented line in .config file
# rppslave
#
#CONFIG_PACKAGE_rppslave=y
#

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=rppslave
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/rppslave
	SECTION:=rppslave
	CATEGORY:=rppslave
        DEPENDS:=+libpthread +librt +libm +swupgrade +pcie_fpga_util
	TITLE:=rppslave
	Package/PKG_NAME/description:=\
    rppslave application to test rpphost
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/rppslave/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rppslave $(1)/usr/bin/
endef

$(eval $(call BuildPackage,rppslave))

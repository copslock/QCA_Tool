# OpenWrt Makefile for pcie_fpga uitlity

# Add the below commented line in .config file
#
#
#CONFIG_PACKAGE_pcie_fpga_util=y
#

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=pcie_fpga_util
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/pcie_fpga_util
        SECTION:=libs
        CATEGORY:=Libraries
        TITLE:=Lib for accessing fpga registers
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/pcie_fpga_util/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pcie_fpga_util $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libpciefpga.so $(1)/lib/
endef

$(eval $(call BuildPackage,pcie_fpga_util))

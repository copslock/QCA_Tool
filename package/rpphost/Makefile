# OpenWrt Makefile for rpphost program

# Add the below commented line in .config file
# rpphost
#
#CONFIG_PACKAGE_rpphost=y
#

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=rpphost
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/rpphost
	SECTION:=rpphost
	CATEGORY:=rpphost
        DEPENDS:=+librt +libm
	TITLE:=rpphost
	Package/PKG_NAME/description:=\
    rpphost application to test rppslave
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/rpphost/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rpphost $(1)/usr/bin/
endef

$(eval $(call BuildPackage,rpphost))

#!/bin/sh

# update and install feeds
./scripts/feeds update -a
./scripts/feeds install -a -f

# copy default config
#cp qca/configs/qsdk/ipq_premium.config .config
cp ipqconfigs/config.ipq .config

sed -i "s/TARGET_ipq_ipq806x/TARGET_ipq_ipq807x_64/g" .config

#make default config
make defconfig

#for pkg_num in 1 2 3 4 5 6 9 11;do sed 's/CONFIG_PACKAGE_qca-wifi-fw-hw'${pkg_num}'-10.4-asic=y/# CONFIG_PACKAGE_qca-wifi-fw-hw'${pkg_num}'-10.4-asic is not set/g' -i .config;done

sed -i -e "/CONFIG_PACKAGE_qca-wifi-fw-hw5-10.4-asic/d" .config

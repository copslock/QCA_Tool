
./scripts/feeds update -a
./scripts/feeds install -a -f
cp qca/configs/qsdk/ipq_premium.config .config
sed -i "s/TARGET_ipq_ipq806x/TARGET_ipq_ipq807x/g" .config
make defconfig
sed -i -e "/CONFIG_PACKAGE_qca-wifi-fw-hw5-10.4-asic/d" .config
make V=s


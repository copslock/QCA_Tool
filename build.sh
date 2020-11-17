#!/bin/bash

init_build=false
version_string=
ipqprofile=ipq3
version_string_prefix=003
ipqimgver=01 # init default minor ver
kclean=
# emulation can be client/AP emulation
emulation=client

ipqprofile=
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in 
        clean)
            clean_build=true
            shift
            ;;
        ipq2)
            echo "Building two radio firmware binaries"        
            ipqprofile=ipq2
            version_string_prefix=002
            export IPQ=IPQ2
            shift
            ;;
        ipq3)
            echo "Building three radio firmware binaries"        
            ipqprofile=ipq3
            version_string_prefix=003
            export IPQ=IPQ3
            shift
            ;;
        version)
            shift
            ipqimgver=$1
            shift
            ;;
        kclean)
            kclean=true
            shift
            ;;
        ap)
            emulation=ap
            shift
            ;;
        *)
            shift
            ;;
    esac
done


if [ "$emulation" = "ap" ];then
    if [ -z $ipqprofile -o "$ipqprofile" = "ipq3" ];then
        version_string_prefix=006
    else
        version_string_prefix=004
    fi
fi
version_string=${version_string_prefix}.${ipqimgver}
echo "IPQ_SW_VERSION ${version_string}" > ./package/base-files/files/etc/ipq_image_version
echo "IPQ_SW_VERSION ${version_string}"

# copy default config

if [ "$clean_build" = true ] || [ ! -d build_dir ]; then
    echo "clean/init build...."
    ./64bit_configure_build.sh
fi

function install_ap_configs()
{
    cp ipqconfigs/revanche.ap package/base-files/files/etc/init.d/revanche
    cp ipqconfigs/config.wlan.unified.profile.ap qca/src/qca-wifi/os/linux/configs/config.wlan.unified.profile
    cp ipqconfigs/config.ipq.ap .config
    cp ipqconfigs/hostapd-default.config.ap qca/feeds/qca/net/qca-hostap/files/hostapd-default.config
    cp ipqconfigs/qcawifi.sh.ap qca/feeds/qca/net/qca-wifi/files/qcawifi.sh
    cp prebuilt/ipq807x_64/PIL_IMAGES_stock/* qca/feeds/qca_hk/net/qca-hk/files/lib/firmware/IPQ8074/
}
function install_sta_configs()
{
    cp ipqconfigs/config.wlan.unified.profile.sta qca/src/qca-wifi/os/linux/configs/config.wlan.unified.profile
    cp ipqconfigs/revanche package/base-files/files/etc/init.d/revanche
    cp ipqconfigs/config.ipq .config
    cp ipqconfigs/qcawifi.sh.sta qca/feeds/qca/net/qca-wifi/files/qcawifi.sh
    cp ipqconfigs/hostapd-default.config.sta qca/feeds/qca/net/qca-hostap/files/hostapd-default.config
}

if [ "$emulation" = "ap" ];then
    echo "building AP emulation Image..."
    install_ap_configs
    git submodule init
    git submodule update
else
    install_sta_configs
fi

pushd qca/src/linux-4.4/arch/arm64/boot/dts/qcom/

# what was the last build done for? IPQ2/IPQ3??
source=`readlink -f qcom-ipq807x-soc.dtsi`
current_ipqprofile=
if [[ $source == *".ipq2" ]]; then
    current_ipqprofile=ipq2
fi
if [[ $source == *".ipq3" ]]; then
    current_ipqprofile=ipq3
fi
popd
# delete dtb files if previos build was for ipq2(ipq3) and new build is for ipq3(ipq2)
if [ "$current_ipqprofile" != "$ipqprofile" ]; then

    if [ "$emulation" != "ap" ];then
	    make package/rppslave/clean
    fi

    pushd qca/src/linux-4.4/arch/arm64/boot/dts/qcom/
    #rm -f qcom-ipq807x-soc.dtsi
    rm -f *.dtb

    #case $ipqprofile in 
    #    ipq3)
    #        ln -sf qcom-ipq807x-soc.dtsi.ipq3 qcom-ipq807x-soc.dtsi
    #        kclean=true
    #        ;;
    #    ipq2)
    #        ln -sf qcom-ipq807x-soc.dtsi.ipq2 qcom-ipq807x-soc.dtsi
    #        kclean=true
    #        ;;
    #    *)
    #        echo "invalid ipq profile ${ipqprofile}!"
    #        exit
    #        ;;
    #esac
    
    popd
fi

if [ "$kclean" = true ]; then
    echo "clean kernel...."
    make target/linux/clean V=s
fi

# update toolchain on kernel-headers
make toolchain/kernel-headers/{clean,compile,install} V=s


ncores=`nproc`
N_DCTHREADS=${ncores} make V=s

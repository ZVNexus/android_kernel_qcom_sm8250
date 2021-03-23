# SPDX-License-Identifier: GPL-2.0

ifeq ($(CONFIG_BUILD_ARM64_DT_OVERLAY),y)
	ifdef CONFIG_MACH_ASUS_ZS661KS
		dtbo-$(CONFIG_ARCH_KONA) += \
			ZS661KS-EVB-overlay.dtbo \
			ZS661KS-SR-overlay.dtbo \
			ZS661KS-ER-overlay.dtbo \
			ZS661KS-ER2-overlay.dtbo \
			ZS661KS-PR-overlay.dtbo \
			ZS661KS-PR2-overlay.dtbo \
			ZS661KS-MP-overlay.dtbo \
	else ifdef CONFIG_MACH_ASUS_ZS670KS
		dtbo-$(CONFIG_ARCH_KONA) += \
			zs670ks-evb-asus-overlay.dtbo \
			zs670ks-sr-asus-overlay.dtbo \
			zs670ks-sr2-asus-overlay.dtbo \
			zs670ks-sr3-asus-overlay.dtbo \
			zs670ks-er-asus-overlay.dtbo \
			zs670ks-pr-asus-overlay.dtbo \
			zs670ks-mp-asus-overlay.dtbo
	endif

        dtbo-$(CONFIG_ARCH_KONA) += \
		kona-mtp-overlay.dtbo

ifdef CONFIG_MACH_ASUS_ZS661KS
	ZS661KS-EVB-overlay.dtbo-base := kona-v2.1.dtb
	ZS661KS-SR-overlay.dtbo-base := kona-v2.1.dtb
	ZS661KS-ER-overlay.dtbo-base := kona-v2.1.dtb
	ZS661KS-ER2-overlay.dtbo-base := kona-v2.1.dtb
	ZS661KS-PR-overlay.dtbo-base := kona-v2.1.dtb
	ZS661KS-PR2-overlay.dtbo-base := kona-v2.1.dtb
	ZS661KS-MP-overlay.dtbo-base := kona-v2.1.dtb
else ifdef CONFIG_MACH_ASUS_ZS670KS
	zs670ks-evb-asus-overlay.dtbo-base := kona-v2.1.dtb
	zs670ks-sr-asus-overlay.dtbo-base := kona-v2.1.dtb
	zs670ks-sr2-asus-overlay.dtbo-base := kona-v2.1.dtb
	zs670ks-sr3-asus-overlay.dtbo-base := kona-v2.1.dtb
	zs670ks-er-asus-overlay.dtbo-base := kona-v2.1.dtb
	zs670ks-pr-asus-overlay.dtbo-base := kona-v2.1.dtb
	zs670ks-mp-asus-overlay.dtbo-base := kona-v2.1.dtb
endif

kona-mtp-overlay.dtbo-base := kona-v2.1.dtb

else

dtb-$(CONFIG_ARCH_KONA) += \
	kona-v2.1-mtp.dtb

endif

always		:= $(dtb-y)
subdir-y	:= $(dts-dirs)
clean-files	:= *.dtb *.dtbo

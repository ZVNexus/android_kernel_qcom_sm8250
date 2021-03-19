# SPDX-License-Identifier: GPL-2.0

ifeq ($(CONFIG_BUILD_ARM64_DT_OVERLAY),y)
	dtbo-$(CONFIG_ARCH_KONA) += \
		ZS661KS-EVB-overlay.dtbo \
		ZS661KS-SR-overlay.dtbo \
		ZS661KS-ER-overlay.dtbo \
		ZS661KS-ER2-overlay.dtbo \
		ZS661KS-PR-overlay.dtbo \
		ZS661KS-PR2-overlay.dtbo \
		ZS661KS-MP-overlay.dtbo \
		kona-mtp-overlay.dtbo

ZS661KS-EVB-overlay.dtbo-base := kona-v2.1.dtb
ZS661KS-SR-overlay.dtbo-base := kona-v2.1.dtb
ZS661KS-ER-overlay.dtbo-base := kona-v2.1.dtb
ZS661KS-ER2-overlay.dtbo-base := kona-v2.1.dtb
ZS661KS-PR-overlay.dtbo-base := kona-v2.1.dtb
ZS661KS-PR2-overlay.dtbo-base := kona-v2.1.dtb
ZS661KS-MP-overlay.dtbo-base := kona-v2.1.dtb
kona-mtp-overlay.dtbo-base := kona-v2.1.dtb
else
dtb-$(CONFIG_ARCH_KONA) += \
	kona-v2.1-mtp.dtb
endif

always		:= $(dtb-y)
subdir-y	:= $(dts-dirs)
clean-files    := *.dtb *.dtbo

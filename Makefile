TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e

# Rootless settings
THEOS_PACKAGE_SCHEME = rootless

INSTALL_TARGET_PROCESSES = YouTube

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = YTKCore

YTKCore_FILES = Tweak.xm
YTKCore_CFLAGS = -fobjc-arc
YTKCore_FRAMEWORKS = UIKit Foundation Security

include $(THEOS_MAKE_PATH)/tweak.mk

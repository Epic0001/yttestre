TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e

# Rootless settings
THEOS_PACKAGE_SCHEME = rootless

INSTALL_TARGET_PROCESSES = YouTube

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = YTCore

YTCore_FILES = Tweak.xm
YTCore_CFLAGS = -fobjc-arc
YTCore_FRAMEWORKS = UIKit Foundation Security

include $(THEOS_MAKE_PATH)/tweak.mk

TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e

# Rootless settings
THEOS_PACKAGE_SCHEME = rootless

INSTALL_TARGET_PROCESSES = YouTube

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = YTKActivator

YTKActivator_FILES = Tweak.xm
YTKActivator_CFLAGS = -fobjc-arc
YTKActivator_FRAMEWORKS = UIKit Foundation Security

include $(THEOS_MAKE_PATH)/tweak.mk
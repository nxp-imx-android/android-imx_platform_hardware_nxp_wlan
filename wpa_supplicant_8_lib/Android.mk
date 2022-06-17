#
# Copyright (C) 2008 The Android Open Source Project
# Copyright 2012-2020 NXP
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)

ifeq ($(WPA_SUPPLICANT_VERSION),VER_0_8_X)

ifneq ($(BOARD_WPA_SUPPLICANT_DRIVER),)
  CONFIG_DRIVER_$(BOARD_WPA_SUPPLICANT_DRIVER) := y
endif

WPA_SUPPL_DIR = external/wpa_supplicant_8
WPA_SRC_FILE :=

include $(WPA_SUPPL_DIR)/wpa_supplicant/android.config
include $(LOCAL_PATH)/android.config

WPA_SUPPL_DIR_INCLUDE = $(WPA_SUPPL_DIR)/src \
	$(WPA_SUPPL_DIR)/src/common \
	$(WPA_SUPPL_DIR)/src/drivers \
	$(WPA_SUPPL_DIR)/src/l2_packet \
	$(WPA_SUPPL_DIR)/src/utils \
	$(WPA_SUPPL_DIR)/src/wps \
	$(WPA_SUPPL_DIR)/wpa_supplicant

ifdef CONFIG_DRIVER_NL80211
ifneq ($(wildcard external/libnl),)
WPA_SUPPL_DIR_INCLUDE += external/libnl/include
else
WPA_SUPPL_DIR_INCLUDE += external/libnl-headers
endif

WPA_SRC_FILE += driver_cmd_nl80211.c
endif

ifdef CONFIG_DRIVER_WEXT
WPA_SRC_FILE += driver_cmd_wext.c
endif

# To force sizeof(enum) = 4
L_CFLAGS_32 += -mabi=aapcs-linux
L_CFLAGS_64 += -mabi=lp64

ifdef CONFIG_ANDROID_LOG
L_CFLAGS += -DCONFIG_ANDROID_LOG
endif

ifdef CONFIG_ANDROID_12
L_CFLAGS += -DANDROID_12
endif

########################

include $(CLEAR_VARS)
LOCAL_MODULE := lib_driver_cmd_nxp
LOCAL_SHARED_LIBRARIES := libc libcutils
LOCAL_CFLAGS := $(L_CFLAGS)
LOCAL_CFLAGS += -Werror -Wno-unused-parameter -Wno-macro-redefined
LOCAL_SRC_FILES := $(WPA_SRC_FILE)
LOCAL_C_INCLUDES := $(WPA_SUPPL_DIR_INCLUDE)
LOCAL_PROPRIETARY_MODULE := true
LOCAL_SANITIZE := cfi
LOCAL_SANITIZE_DIAG := cfi
include $(BUILD_STATIC_LIBRARY)

########################

endif

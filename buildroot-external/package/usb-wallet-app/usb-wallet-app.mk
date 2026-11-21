################################################################################
#
# usb-wallet-app
#
################################################################################

USB_WALLET_APP_VERSION = 0.1.0
USB_WALLET_APP_SITE = $(BR2_EXTERNAL_USB_WALLET_PATH)/..
USB_WALLET_APP_SITE_METHOD = local
USB_WALLET_APP_OVERRIDE_SRCDIR_RSYNC_EXCLUSIONS = --exclude build/ --exclude .venv/
USB_WALLET_APP_LICENSE = MIT
USB_WALLET_APP_LICENSE_FILES = LICENSE
USB_WALLET_APP_DEPENDENCIES = python3

define USB_WALLET_APP_INSTALL_TARGET_CMDS
	$(HOST_DIR)/bin/python3 $(@D)/scripts/install_target_python.py \
		--source $(@D) \
		--wheelhouse $(BR2_EXTERNAL_USB_WALLET_PATH)/../build/wheelhouse \
		--target $(TARGET_DIR)
endef

$(eval $(generic-package))

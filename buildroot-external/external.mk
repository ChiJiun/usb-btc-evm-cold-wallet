include $(sort $(wildcard $(BR2_EXTERNAL_USB_WALLET_PATH)/package/*/*.mk))

# Python is intentionally built without Tk by upstream Buildroot. The offline
# signer GUI already uses tkinter, so enable only this local GUI dependency.
ifeq ($(BR2_PACKAGE_USB_WALLET_APP),y)
PYTHON3_CONF_OPTS := $(filter-out --disable-tk,$(PYTHON3_CONF_OPTS))
PYTHON3_CONF_OPTS += --enable-tk
PYTHON3_DEPENDENCIES += tk
endif

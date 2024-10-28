#
# Copyright (c) 2020-2024 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

.PHONY: all
all: suit_manifest_expU.cbor.h config.json.h suit_manifest_expS1.cbor.h encrypted_image_aes.bin.h

%.h: %
	xxd -i $< | sed -e 's/^unsigned char/const uint8_t/' -e 's/^unsigned int/const size_t/' > $@

.PHONY: clean
clean:
	$(RM) *.h

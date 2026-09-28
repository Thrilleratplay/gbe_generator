#!/usr/bin/env python

# cspell: words unhexlify sicw ADBA iscsi iboot lplu undi
"""Intel Gigabit Ethernet binary firmware generator."""

from binascii import unhexlify
from typing import Union, List
import argparse
import re
import sys

word_byte_type = Union[int, List[int]]


def is_valid_model(model: str):
    """Test if string is a supported model number"""
    lc_model = model.lower()
    if lc_model == '82579lm' or \
       lc_model == '82579v' or \
       lc_model == 'i217lm' or \
       lc_model == 'i217v' or \
       lc_model == 'i218lm' or \
       lc_model == 'i218v' or \
       lc_model == 'i219lm' or \
       lc_model == 'i219v':
        return lc_model
    else:
        raise argparse.ArgumentTypeError(
            f"{model} is not a 82579LM,82579V,i217LM,",
            "i217V,i218LM,i218V,i219LM, or i219V"
        )


def is_mac_address(mac: str):
    """Test if string is a valid MAC Address"""
    lc_mac = mac.lower()
    # https://stackoverflow.com/a/7629690
    if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", lc_mac):
        return mac
    else:
        raise argparse.ArgumentTypeError(
            f"{mac} is not a valid MAC Address"
        )


class WordByte:
    """Single byte of word"""
    byte_value: int

    def __init__(self, value: word_byte_type):
        if isinstance(value, List):
            self.byte_value = self.from_bitmap_array(value)
        elif isinstance(value, int):
            self.byte_value = value
        else:
            self.byte_value = 0

    def from_bitmap_array(self, bitmap_array):
        """Convert bitmap array to integer."""
        value = 0
        for i, item in enumerate(bitmap_array):
            if int(item) == 1:
                value += 2**i
        return value

    @property
    def binary(self):
        """Convert to binary"""
        hex_value = hex(self.byte_value)[2:]
        if len(hex_value) % 2 == 0:
            return unhexlify(hex_value)
        else:
            return unhexlify('0' + hex_value)


class Word:
    """Firmware Word."""
    byte_1: WordByte
    byte_2: WordByte

    def __init__(self, b1_val: word_byte_type, b2_val: word_byte_type) -> None:
        """Init."""
        self.byte_1 = WordByte(b1_val)
        self.byte_2 = WordByte(b2_val)

    @property
    def int_value(self):
        """Integer value of bytes"""
        return self.byte_1.byte_value + self.byte_2.byte_value

    @property
    def binary(self):
        """Binary value of bytes"""
        return self.byte_1.binary + self.byte_2.binary


class GbeGenerateShared:
    """Generate 82579 GBE blob."""

    def generate_padding(self, length: int) -> bytes:
        """Generate padding of a given length"""
        padding = unhexlify("ff")
        i = length - 1
        while i > 0:
            padding += unhexlify("ff")
            i -= 1
        return padding

    def add_checksum(self, blob: bytes) -> bytes:
        """Append checksum to blob."""
        word_sum = 0
        # iterates over bytes (NVM 0x00-0x7E)
        for i, item in enumerate(blob):
            if i % 2 == 0:
                word_sum += item
            else:
                word_sum += item << 8
        checksum_int = 0xbaba - (word_sum & 0xffff)
        hex_value = hex(checksum_int)[2:]
        if len(hex_value) == 3:
            hex_value = '0' + hex_value
        checksum = hex_value[2:4] + hex_value[0:2]

        return blob + unhexlify(checksum)

    @property
    def reserved_word_x03(self) -> bytes:
        """Reserved (Word 0x3) - Used by software"""
        return Word(0x00, 0x08).binary

    @property
    def reserved_word_x04(self) -> bytes:
        """Reserved (Word 0x04) - Used by software"""
        return Word(0xff, 0xff).binary

    @property
    def reserved_word_x06(self) -> bytes:
        """# Reserved (Word 0x06) - Used by software"""
        return Word(0xff, 0xff).binary

    @property
    def reserved_word_x07(self) -> bytes:
        """# Reserved (Word 0x07) - Used by software"""
        return Word(0xff, 0xff).binary

    @property
    def pba_low_x08(self) -> bytes:
        """PBA Low (Words 0x08) - Used by software"""
        return Word(0xff, 0xff).binary

    @property
    def pba_high_x09(self) -> bytes:
        """PBA High (Words 0x08) - Used by software"""
        return Word(0xff, 0xff).binary

    @property
    def pci_init_control_x0a(self) -> bytes:
        """PCI Init Control Word (Word 0x0A) - Used by Hardware-PCI"""
        return Word([
            1,  # AUX PWR#
            1,  # PM Enable
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
            1,  # Load Subsystem IDs
            1   # Load Device IDs
        ], 0x10).binary

    @property
    def subsystem_id_x0b(self) -> bytes:
        """Subsystem ID (Word 0x0B) - Used by Hardware-PCI"""
        return Word(0x00, 0x00).binary

    @property
    def subsystem_vendor_id_x0c(self) -> bytes:
        """Subsystem Vendor ID (Word 0x0C) - Used by Hardware-PCI"""
        return Word(0x86, 0x80).binary

    @property
    def reserved_x0e(self) -> bytes:
        """Reserved (Word 0x0E) - Used by Hardware-PCI"""
        return Word(0x00, 0x00).binary

    @property
    def reserved_x0f(self) -> bytes:
        """Reserved (Word 0x0F) - Used by Hardware-PCI"""
        return Word(0x00, 0x00).binary

    @property
    def lan_power_x10(self) -> bytes:
        """LAN Power Consumption (Word 0x10) - Used by Hardware-PCI"""
        return Word(0x02, 0x07).binary

    @property
    def reserved_x11(self) -> bytes:
        """Reserved (Word 0x11) - Used by Hardware"""
        return Word(0x00, 0x00).binary

    @property
    def reserved_x12(self) -> bytes:
        """Reserved (Word 0x12) - Used by Hardware"""
        return Word(0x00, 0x00).binary

    @property
    def sicw_x13(self) -> bytes:
        """Shared Init Control Word (Word 0x13) - Used by Hardware-Shared"""
        return Word([
            1,  # Dynamic clock gating
            0,  # Clock count, when set, automatically reduces DMA frequency
            1,  # Reserved
            0,  # Full Duplex bit in the Device Control register
            0,  # Force Speed bit in the Device Control register
            0,  # Reserved
            0,  # PHY Device Type
            0,  # PHY Device Type
        ], [
            1,  # Sign
            0,  # Sign
            1,  # MACsec disable
            0,  # Reserved
            0,  # Reserved
            1,  # Reserved
            0,  # Enable PHY Power Down
            1   # Reserved
        ]).binary

    @property
    def ecw1_x14(self) -> bytes:
        """Extended Configuration Word 1 (Word 0x14) - Used by HW-Shared"""
        return Word(0x30, [
          0,
          0,
          0,
          0,
          1,  # OEM Write Enable
          1,  # PHY Write Enable
          0,  # Reserved
          0,  # Reserved
        ]).binary

    @property
    def ecw2_x15(self) -> bytes:
        """Extended Configuration Word 2 (Word 0x15) - Used by HW-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def ecw3_x16(self) -> bytes:
        """Extended Configuration Word 3 (Word 0x16) - Used by HW-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def oem_x17(self) -> bytes:
        """ OEM Configuration Defaults (Word 0x17) - Used by Hardware-Shared"""
        # Data sheet PDF: 10.3.1.13
        return Word(0x00, [
          0,
          0,  # Low Power Link Up enable in d0a
          1,  # Low Power Link Up enable in non d0a
          1,  # GBE disable in non d0a
          0,  # Reserved
          0,  # Reserved
          0,  # GBE disable
          0,  # B2B enable
         ]).binary

    @property
    def led_x18(self) -> bytes:
        """LED 0 - 2 Configuration Defaults (Word 0x18) - Used by HW-Shared"""
        # Lenovo default values
        return Word([
          0,  # LED 1 Mode
          0,  # LED 1 Mode
          1,  # LED 1 Mode
          0,  # LED 0 Blink
          0,  # LED 0 Invert
          1,  # LED 0 Mode
          1,  # LED 0 Mode
          0,  # LED 0 Mode
        ], [
          0,  # Blink Rate
          1,  # LED 2 Blink
          0,  # LED 2 Invert
          1,  # LED 2 Mode
          0,  # LED 2 Mode
          1,  # LED 2 Mode
          0,  # LED 1 Blink
          0,  # LED 1 Invert
        ]).binary

    @property
    def reserved_x19(self) -> bytes:
        """Reserved (Word 0x19) - Used by Hardware-Shared"""
        return Word(0x00, 0x0A).binary

    @property
    def amp_x1a(self) -> bytes:
        """Reserved (Word 0x1A) - Used by Hardware-Shared"""
        # Advanced Power Management Wake Up Enable
        return Word([
          1,  # APM Enable
          0,
          0,
          0,
          0,
          0,
          0,
          0,
        ], [
          0,
          0,
          0,
          0,
          0,
          0,
          0,
          0,
        ]).binary

    @property
    def reserved_x1b(self) -> bytes:
        """Reserved (Word 0x1B) - Used by Hardware-Shared"""
        return Word(0x13, 0x01).binary

    @property
    def reserved_x1c(self) -> bytes:
        """Reserved (Word 0x1C) - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def reserved_x1d(self) -> bytes:
        """Reserved (Word 0x1D) - Used by Hardware-Shared"""
        return Word(0xAD, 0xBA).binary

    @property
    def reserved_x1e(self) -> bytes:
        """Reserved (Word 0x1E) - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def reserved_x1f(self) -> bytes:
        """Reserved (Word 0x1F) - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def reserved_x20(self) -> bytes:
        """Reserved (Word 0x20) - Used by Hardware-Shared"""
        return Word(0xAD, 0xBA).binary

    @property
    def reserved_x21(self) -> bytes:
        """Reserved (Word 0x21) - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def reserved_x22(self) -> bytes:
        """Reserved (Word 0x22) - Used by Hardware-Shared"""
        return Word(0xAD, 0xBA).binary

    @property
    def reserved_x23(self) -> bytes:
        """Reserved (Word 0x23) - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def reserved_x24(self) -> bytes:
        """Reserved (Word 0x24) - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def reserved_x25(self) -> bytes:
        """Reserved (Word 0x25) - Used by Hardware-Shared"""
        return Word(0x80, 0x80).binary

    @property
    def reserved_x26(self) -> bytes:
        """Reserved (Word 0x26) - Used by Hardware-Shared"""
        return Word(0x00, 0x4E).binary

    @property
    def reserved_x27(self) -> bytes:
        """Reserved (Word 0x27) - Used by Hardware-Shared"""
        return Word(0x80, 0x86).binary

    @property
    def offset_x28(self) -> bytes:
        """Offsets 0x28 - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def offset_x29(self) -> bytes:
        """Offsets 0x29 - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def offset_x2a(self) -> bytes:
        """Offsets 0x2a - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def offset_x2b(self) -> bytes:
        """Offsets 0x2b - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def offset_x2c(self) -> bytes:
        """Offsets 0x2c - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def offset_x2d(self) -> bytes:
        """Offsets 0x2d - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def offset_x2e(self) -> bytes:
        """Offsets 0x2e - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def offset_x2f(self) -> bytes:
        """Offsets 0x2f - Used by Hardware-Shared"""
        return Word(0x00, 0x00).binary

    @property
    def pxe_x30(self) -> bytes:
        """Boot Agent Main Setup Options (Word 0x30) - Used by PXE"""
        # Hardcoded PXE setup (disabled)
        return Word([
            0,  # Protocol Select
            0,  # Protocol Select
            0,  # Reserved
            1,  # Default Boot Selection
            1,  # Default Boot Selection
            0,  # Reserved
            1,  # Prompt Time
            1,  # Prompt Time
        ], [
            0,  # Display Setup Message
            0,  # Reserved
            0,  # Force Speed
            0,  # Force Speed
            0,  # Force Full Duplex
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
        ]).binary

    @property
    def pxe_x31(self) -> bytes:
        """Boot Agent Configuration Customization Options (Word 0x31)"""
        #  Used by PXE
        return Word([
            1,  # Disable Setup Menu
            1,  # Disable Title Message
            0,  # Disable Protocol Select
            0,  # Disable Boot Selection
            0,  # Disable Legacy Wakeup Support
            0,  # Disable Flash Update
            0,  # Reserved
        ], [
            0,  # Reserved
            0,  # Agent's Boot order setup mode
            0,  # Agent's Boot order setup mode
            0,  # Agent's Boot order setup mode
            0,  # Continuous Retry Disabled
            0,  # Reserved
            0,  # Reserved
            1,  # Signature
        ]).binary

    @property
    def pxe_x32(self) -> bytes:
        """Boot Agent Configuration Customization Options (Word 0x32)"""
        #  Used by PXE
        return Word(0x28, 0x12).binary

    @property
    def pxe_x33(self) -> bytes:
        """IBA Capabilities (Word 0x33) - Used by PXE"""
        return Word([
            1,  # PXE base code is present
            1,  # PXE/UNDI capability is present
            1,  # Reserved
            0,  # EFI EBC capability is present
            0,  # iSCSI Boot Capability not present
            0,  # Reserved
            0,  # Reserved
        ], [
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
            0,  # Signature
            1,  # Signature
        ]).binary


class GbeGenerate(GbeGenerateShared):
    """Generate 82579 GBE blob."""

    mac_address: bytes
    blob: bytes

    def __init__(
        self,
        mac: str,
        model: str,
        file_name: str,
        mobile: bool = False,
        lan_switch: bool = False,
    ) -> None:
        """Init."""

        self.mac_address = unhexlify(mac)
        if model == '82579lm':
            self.blob = self.generate_82579_blob(mobile=mobile)
        elif model == '82579v':
            self.blob = self.generate_82579_blob(is_82579v=True, mobile=mobile)
        elif model == 'i217lm':
            self.blob = self.generate_i217_blob(
                is_i217v=False,
                lan_switch=lan_switch
            )
        elif model == 'i217v':
            self.blob = self.generate_i217_blob(
                is_i217v=True,
                lan_switch=lan_switch
            )
        elif model == 'i218lm':
            self.blob = self.generate_i218_blob(
                is_i218v=False,
                lan_switch=lan_switch
            )
        elif model == 'i218v':
            self.blob = self.generate_i218_blob(
                is_i218v=True,
                lan_switch=lan_switch
            )
        elif model == 'i219lm':
            self.blob = self.generate_i219_blob(
                is_i219v=False,
                lan_switch=lan_switch
            )
        elif model == 'i219v':
            self.blob = self.generate_i219_blob(
                is_i219v=True,
                lan_switch=lan_switch
            )

        if self.blob is not None:
            self.write_blob(file_name)

    def write_blob(self, file_name: str) -> None:
        """Generate GBE blob."""
        fo = open(file_name, "wb")
        fo.write(self.blob + self.blob)
        fo.close()

    def generate_g3_s5_configuration(self) -> bytes:
        """Generate padding of a given length"""
        padding = unhexlify("00")
        i = 0
        while i < 21:
            padding += unhexlify("00")
            i += 1
        return padding

    def generate_82579_blob(
        self,
        is_82579v: bool = False,
        mobile: bool = False
    ) -> bytes:
        """Generate 82579 blob"""

        # Data sheet PDF: 10.3.1.5
        # Device ID (Word 0x0D) - Used by Hardware-PCI
        deviceid_x0d = Word(0x03, 0x15) if is_82579v else Word(0x02, 0x15)

        # Image Version Information (Word 0x05) - Used by software
        # Data sheet PDF: 10.3.3.3
        image_version_info_x05 = Word(0xd3, 0x00).binary if mobile \
            else Word(0xd4, 0x00).binary

        # Extended Configuration Word 1 (Word 0x14) - Used by HW-Shared
        # Data sheet PDF: 10.3.1.10
        ecw1_x14 = Word(0x28, [
          0,
          0,
          0,
          0,
          1,  # OEM Write Enable
          1,  # PHY Write Enable
          0,  # Reserved
          0,  # Reserved
        ]).binary

        # Extended Configuration Word 2 (Word 0x15) - Used by HW-Shared
        # Data sheet PDF: 10.3.1.11
        ecw2_x15 = Word(0x00, 0x12).binary

        # OEM Configuration Defaults (Word 0x17) - Used by Hardware-Shared
        # Data sheet PDF: 10.3.1.13
        oem_x17 = Word(0x00, [
          0,
          0,  # Low Power Link Up enable in d0a
          1,  # Low Power Link Up enable in non d0a
          1,  # GBE disable in non d0a
          0,  # Reserved
          0,  # Reserved
          0,  # GBE disable
          0,  # Reserved
         ]).binary

        # Reserved (Word 0x19) - Used by Hardware-Shared
        # Data sheet PDF: 10.3.1.15
        # NOTE: bit 6 must be 1 for validation.  See data sheet.
        reserved_x19 = Word(0x40, 0x2B).binary

        # Reserved (Word 0x1A) - Used by Hardware-Shared
        # Advanced Power Management Wake Up Enable
        amp_x1a = Word([
          1,  # APM Enable
          1,
          0,
          0,
          0,
          0,
          1,
          0,
        ], [
          0,
          0,
          0,
          1,
          0,
          0,
          0,
          0,
        ]).binary

        # Reserved (Word 0x1C) - Used by Hardware-Shared
        reserved_x1c = Word(0x02, 0x15).binary

        # Reserved (Word 0x1E) - Used by Hardware-Shared
        reserved_x1e = Word(0x02, 0x15).binary

        # Reserved (Word 0x1F) - Used by Hardware-Shared
        reserved_x1f = Word(0x03, 0x15).binary

        # Reserved (Word 0x21) - Used by Hardware-Shared
        reserved_x21 = Word(0xAD, 0xBA).binary

        # Reserved (Word 0x23) - Used by Hardware-Shared
        reserved_x23 = Word(0x02, 0x15).binary

        # Reserved (Word 0x24) - Used by Hardware-Shared
        # Data sheet PDF: 10.3.1.26
        reserved_x24 = Word(0x00, [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
           ]).binary

        # Reserved (Word 0x25) - Used by Hardware-Shared
        # Data sheet PDF: 10.3.1.27
        reserved_x25 = Word([
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            1,
        ], [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
        ]).binary

        # Reserved (Word 0x26) - Used by Hardware-Shared
        # Data sheet PDF: 10.3.1.28
        reserved_x26 = Word(0x00, [
            0,
            1,
            1,
            1,
            0,
            0,
            1,
            0,
        ]).binary

        # Reserved (Word 0x27) - Used by Hardware-Shared
        reserved_x27 = Word(0x80, 0x00).binary

        blob = bytearray(
            self.mac_address  # Data sheet PDF: 10.3.1.1
            + self.reserved_word_x03  # Data sheet PDF: 10.3.3.1
            + self.reserved_word_x04  # Data sheet PDF: 10.3.3.2
            + image_version_info_x05  # Data sheet PDF: 10.3.3.3
            + self.reserved_word_x06
            + self.reserved_word_x07
            + self.pba_low_x08  # Data sheet PDF: 10.3.3.4
            + self.pba_high_x09  # Data sheet PDF: 10.3.3.4
            + self.pci_init_control_x0a  # Data sheet PDF: 10.3.1.2
            + self.subsystem_id_x0b   # Data sheet PDF: 10.3.1.3
            + self.subsystem_vendor_id_x0c  # Data sheet PDF: 10.3.1.4
            + deviceid_x0d.binary  # Data sheet PDF: 10.3.1.5
            + self.reserved_x0e  # Data sheet PDF: 10.3.1.6
            + self.reserved_x0f  # Data sheet PDF: 10.3.1.6
            + self.lan_power_x10  # Data sheet PDF: 10.3.1.7
            + self.reserved_x11  # Data sheet PDF: 10.3.1.8
            + self.reserved_x12  # Data sheet PDF: 10.3.1.8
            + self.sicw_x13  # Data sheet PDF: 10.3.1.9
            + ecw1_x14  # Data sheet PDF: 10.3.1.10
            + ecw2_x15  # Data sheet PDF: 10.3.1.11
            + self.ecw3_x16  # Data sheet PDF: 10.3.1.12
            + oem_x17  # Data sheet PDF: 10.3.1.13
            + self.led_x18  # Data sheet PDF: 10.3.1.14
            + reserved_x19  # Data sheet PDF: 10.3.1.15
            + amp_x1a  # Data sheet PDF: 10.3.1.16
            + self.reserved_x1b  # Data sheet PDF: 10.3.1.17
            + reserved_x1c  # Data sheet PDF: 10.3.1.18
            + self.reserved_x1d  # Data sheet PDF: 10.3.1.19
            + reserved_x1e  # Data sheet PDF: 10.3.1.20
            + reserved_x1f  # Data sheet PDF: 10.3.1.21
            + self.reserved_x20  # Data sheet PDF: 10.3.1.22
            + reserved_x21  # Data sheet PDF: 10.3.1.23
            + self.reserved_x22  # Data sheet PDF: 10.3.1.24
            + reserved_x23  # Data sheet PDF: 10.3.1.25
            + reserved_x24  # Data sheet PDF: 10.3.1.26
            + reserved_x25  # Data sheet PDF: 10.3.1.27
            + reserved_x26  # Data sheet PDF: 10.3.1.28
            + reserved_x27
            + self.offset_x28
            + self.offset_x29
            + self.offset_x2a
            + self.offset_x2b
            + self.offset_x2c
            + self.offset_x2d
            + self.offset_x2e
            + self.offset_x2f
            + self.pxe_x30  # Data sheet PDF: 10.3.2.1.1
            + self.pxe_x31  # Data sheet PDF: 10.3.2.1.2
            + self.pxe_x32  # Data sheet PDF: 10.3.2.1.3
            + self.pxe_x33  # Data sheet PDF: 10.3.2.1.4
            + self.generate_padding(22)
        )
        blob = self.add_checksum(blob)  # Data sheet PDF: 10.3.2.2
        blob += self.generate_g3_s5_configuration()
        blob += self.generate_padding(3946)

        return blob

    def generate_i217_blob(
        self,
        is_i217v: bool = False,
        lan_switch: bool = False
    ) -> bytes:
        """Generate i217 blob"""

        # Data sheet PDF: 9.3.1.5
        # Device ID (Word 0x0D) - Used by Hardware-PCI
        deviceid_x0d = Word(0x3B, 0x15) if is_i217v else Word(0x3A, 0x15)

        # Image Version Information (Word 0x05) - Used by software
        # Data sheet PDF: 9.3.3.3
        image_version_info_x05 = Word(0x03, 0x00).binary if lan_switch \
            else Word(0x04, 0x00).binary

        blob = bytearray(
            self.mac_address  # Data sheet PDF: 9.3.1.1
            + self.reserved_word_x03  # Data sheet PDF: 9.3.3.1
            + self.reserved_word_x04  # Data sheet PDF: 9.3.3.2
            + image_version_info_x05  # Data sheet PDF: 9.3.3.3
            + self.reserved_word_x06
            + self.reserved_word_x07
            + self.pba_low_x08  # Data sheet PDF: 9.3.3.4
            + self.pba_high_x09  # Data sheet PDF: 9.3.3.4
            + self.pci_init_control_x0a  # Data sheet PDF: 9.3.1.2
            + self.subsystem_id_x0b   # Data sheet PDF: 9.3.1.3
            + self.subsystem_vendor_id_x0c  # Data sheet PDF: 9.3.1.4
            + deviceid_x0d.binary   # Data sheet PDF: 9.3.1.5
            + self.reserved_x0e  # Data sheet PDF: 9.3.1.6
            + self.reserved_x0f  # Data sheet PDF: 9.3.1.6
            + self.lan_power_x10  # Data sheet PDF: 9.3.1.7
            + self.reserved_x11  # Data sheet PDF: 9.3.1.8
            + self.reserved_x12  # Data sheet PDF: 9.3.1.8
            + self.sicw_x13  # Data sheet PDF: 9.3.1.9
            + self.ecw1_x14  # Data sheet PDF: 9.3.1.10
            + self.ecw2_x15  # Data sheet PDF: 9.3.1.11
            + self.ecw3_x16  # Data sheet PDF: 9.3.1.12
            + self.oem_x17  # Data sheet PDF: 9.3.1.13
            + self.led_x18  # Data sheet PDF: 9.3.1.14
            + self.reserved_x19  # Data sheet PDF: 9.3.1.15
            + self.amp_x1a  # Data sheet PDF: 9.3.1.16
            + self.reserved_x1b  # Data sheet PDF: 9.3.1.17
            + self.reserved_x1c  # Data sheet PDF: 9.3.1.18
            + self.reserved_x1d  # Data sheet PDF: 9.3.1.19
            + self.reserved_x1e  # Data sheet PDF: 9.3.1.20
            + self.reserved_x1f  # Data sheet PDF: 9.3.1.21
            + self.reserved_x20  # Data sheet PDF: 9.3.1.22
            + self.reserved_x21  # Data sheet PDF: 9.3.1.23
            + self.reserved_x22  # Data sheet PDF: 9.3.1.24
            + self.reserved_x23  # Data sheet PDF: 9.3.1.25
            + self.reserved_x24  # Data sheet PDF: 9.3.1.26
            + self.reserved_x25  # Data sheet PDF: 9.3.1.27
            + self.reserved_x26  # Data sheet PDF: 9.3.1.28
            + self.reserved_x27  # Data sheet PDF: 9.3.1.29
            + self.offset_x28
            + self.offset_x29
            + self.offset_x2a
            + self.offset_x2b
            + self.offset_x2c
            + self.offset_x2d
            + self.offset_x2e
            + self.offset_x2f
            + self.pxe_x30  # Data sheet PDF: 9.3.2.1.1
            + self.pxe_x31  # Data sheet PDF: 9.3.2.1.2
            + self.pxe_x32  # Data sheet PDF: 9.3.2.1.3
            + self.pxe_x33  # Data sheet PDF: 9.3.2.1.4
            + self.generate_padding(22)
        )
        blob = self.add_checksum(blob)  # Data sheet PDF: 10.3.2.2
        blob += self.generate_g3_s5_configuration()
        blob += self.generate_padding(3946)

        return blob

    def generate_i218_blob(
        self,
        is_i218v: bool = False,
        lan_switch: bool = False
    ) -> bytes:
        """Generate i218 blob"""

        # Data sheet PDF: 9.3.1.5
        # Device ID (Word 0x0D) - Used by Hardware-PCI
        deviceid_x0d = Word(0x59, 0x15) if is_i218v else Word(0x5A, 0x15)

        # Image Version Information (Word 0x05) - Used by software
        # Data sheet PDF: 9.3.3.3
        image_version_info_x05 = Word(0x03, 0x00).binary if lan_switch \
            else Word(0x04, 0x00).binary

        blob = bytearray(
            self.mac_address  # Data sheet PDF: 9.3.1.1
            + self.reserved_word_x03  # Data sheet PDF: 9.3.3.1
            + self.reserved_word_x04  # Data sheet PDF: 9.3.3.2
            + image_version_info_x05  # Data sheet PDF: 9.3.3.3
            + self.reserved_word_x06
            + self.reserved_word_x07
            + self.pba_low_x08  # Data sheet PDF: 9.3.3.4
            + self.pba_high_x09  # Data sheet PDF: 9.3.3.4
            + self.pci_init_control_x0a  # Data sheet PDF: 9.3.1.2
            + self.subsystem_id_x0b   # Data sheet PDF: 9.3.1.3
            + self.subsystem_vendor_id_x0c  # Data sheet PDF: 9.3.1.4
            + deviceid_x0d.binary   # Data sheet PDF: 9.3.1.5
            + self.reserved_x0e  # Data sheet PDF: 9.3.1.6
            + self.reserved_x0f  # Data sheet PDF: 9.3.1.6
            + self.lan_power_x10  # Data sheet PDF: 9.3.1.7
            + self.reserved_x11  # Data sheet PDF: 9.3.1.8
            + self.reserved_x12  # Data sheet PDF: 9.3.1.8
            + self.sicw_x13  # Data sheet PDF: 9.3.1.9
            + self.ecw1_x14  # Data sheet PDF: 9.3.1.10
            + self.ecw2_x15  # Data sheet PDF: 9.3.1.11
            + self.ecw3_x16  # Data sheet PDF: 9.3.1.12
            + self.oem_x17  # Data sheet PDF: 9.3.1.13
            + self.led_x18  # Data sheet PDF: 9.3.1.14
            + self.reserved_x19  # Data sheet PDF: 9.3.1.15
            + self.amp_x1a  # Data sheet PDF: 9.3.1.16
            + self.reserved_x1b  # Data sheet PDF: 9.3.1.17
            + self.reserved_x1c  # Data sheet PDF: 9.3.1.18
            + self.reserved_x1d  # Data sheet PDF: 9.3.1.19
            + self.reserved_x1e  # Data sheet PDF: 9.3.1.20
            + self.reserved_x1f  # Data sheet PDF: 9.3.1.21
            + self.reserved_x20  # Data sheet PDF: 9.3.1.22
            + self.reserved_x21  # Data sheet PDF: 9.3.1.23
            + self.reserved_x22  # Data sheet PDF: 9.3.1.24
            + self.reserved_x23  # Data sheet PDF: 9.3.1.25
            + self.reserved_x24  # Data sheet PDF: 9.3.1.26
            + self.reserved_x25  # Data sheet PDF: 9.3.1.27
            + self.reserved_x26  # Data sheet PDF: 9.3.1.28
            + self.reserved_x27  # Data sheet PDF: 9.3.1.29
            + self.offset_x28
            + self.offset_x29
            + self.offset_x2a
            + self.offset_x2b
            + self.offset_x2c
            + self.offset_x2d
            + self.offset_x2e
            + self.offset_x2f
            + self.pxe_x30  # Data sheet PDF: 9.3.2.1.1
            + self.pxe_x31  # Data sheet PDF: 9.3.2.1.2
            + self.pxe_x32  # Data sheet PDF: 9.3.2.1.3
            + self.pxe_x33  # Data sheet PDF: 9.3.2.1.4
            + self.generate_padding(22)
        )
        blob = self.add_checksum(blob)  # Data sheet PDF: 10.3.2.2
        blob += self.generate_g3_s5_configuration()
        blob += self.generate_padding(3946)

        return blob

    def generate_i219_blob(
        self,
        is_i219v: bool = False,
        lan_switch: bool = False
    ) -> bytes:
        """Generate i219 blob"""

        # Data sheet PDF: 10.3.1.5
        # Device ID (Word 0x0D) - Used by Hardware-PCI
        deviceid_x0d = Word(0xB7, 0x15) if is_i219v else Word(0x6F, 0x15)

        # Image Version Information (Word 0x05) - Used by software
        # Data sheet PDF: 10.3.3.3
        image_version_info_x05 = Word(0x03, 0x00).binary if lan_switch \
            else Word(0x04, 0x00).binary

        # Shared Init Control Word (Word 0x13) - Used by Hardware-Shared
        # # Data sheet PDF: 10.3.1.9
        sicw_x13 = Word([
            1,  # Dynamic clock gating
            0,  # Clock count, when set, automatically reduces DMA frequency
            1,  # Reserved
            0,  # Full Duplex bit in the Device Control register
            0,  # Force Speed bit in the Device Control register
            0,  # Reserved
            0,  # PHY Device Type
            0,  # PHY Device Type
        ], [
            1,  # Sign
            0,  # Sign
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
            1,  # Reserved
            0,  # Enable PHY Power Down
            1   # Reserved
        ]).binary

        # OEM Configuration Defaults (Word 0x17) - Used by Hardware-Shared
        # Data sheet PDF: 10.3.1.13
        oem_x17 = Word(0x00, [
          1,  # SPD Enable
          0,  # Low Power Link Up enable in d0a
          1,  # Low Power Link Up enable in non d0a
          1,  # GBE disable in non d0a
          0,  # Reserved
          0,  # Reserved
          0,  # GBE disable
          0,  # Reserved
         ]).binary

        blob = bytearray(
            self.mac_address  # Data sheet PDF: 10.3.1.1
            + self.reserved_word_x03  # Data sheet PDF: 10.3.3.1
            + self.reserved_word_x04  # Data sheet PDF: 10.3.3.2
            + image_version_info_x05  # Data sheet PDF: 10.3.3.3
            + self.reserved_word_x06
            + self.reserved_word_x07
            + self.pba_low_x08  # Data sheet PDF: 10.3.3.4
            + self.pba_high_x09  # Data sheet PDF: 10.3.3.4
            + self.pci_init_control_x0a  # Data sheet PDF: 10.3.1.2
            + self.subsystem_id_x0b   # Data sheet PDF: 10.3.1.3
            + self.subsystem_vendor_id_x0c  # Data sheet PDF: 10.3.1.4
            + deviceid_x0d.binary   # Data sheet PDF: 10.3.1.5
            + self.reserved_x0e  # Data sheet PDF: 10.3.1.6
            + self.reserved_x0f  # Data sheet PDF: 10.3.1.6
            + self.lan_power_x10  # Data sheet PDF: 10.3.1.7
            + self.reserved_x11  # Data sheet PDF: 10.3.1.8
            + self.reserved_x12  # Data sheet PDF: 10.3.1.8
            + sicw_x13  # Data sheet PDF: 10.3.1.9
            + self.ecw1_x14  # Data sheet PDF: 10.3.1.10
            + self.ecw2_x15  # Data sheet PDF: 10.3.1.11
            + self.ecw3_x16  # Data sheet PDF: 10.3.1.12
            + oem_x17  # Data sheet PDF: 10.3.1.13
            + self.led_x18  # Data sheet PDF: 10.3.1.14
            + self.reserved_x19  # Data sheet PDF: 10.3.1.15
            + self.amp_x1a  # Data sheet PDF: 10.3.1.16
            + self.reserved_x1b  # Data sheet PDF: 10.3.1.17
            + self.reserved_x1c  # Data sheet PDF: 10.3.1.18
            + self.reserved_x1d  # Data sheet PDF: 10.3.1.19
            + self.reserved_x1e  # Data sheet PDF: 10.3.1.20
            + self.reserved_x1f  # Data sheet PDF: 10.3.1.21
            + self.reserved_x20  # Data sheet PDF: 10.3.1.22
            + self.reserved_x21  # Data sheet PDF: 10.3.1.23
            + self.reserved_x22  # Data sheet PDF: 10.3.1.24
            + self.reserved_x23  # Data sheet PDF: 10.3.1.25
            + self.reserved_x24  # Data sheet PDF: 10.3.1.26
            + self.reserved_x25  # Data sheet PDF: 10.3.1.27
            + self.reserved_x26  # Data sheet PDF: 10.3.1.28
            + self.reserved_x27  # Data sheet PDF: 10.3.1.29
            + self.offset_x28
            + self.offset_x29
            + self.offset_x2a
            + self.offset_x2b
            + self.offset_x2c
            + self.offset_x2d
            + self.offset_x2e
            + self.offset_x2f
            + self.pxe_x30  # Data sheet PDF: 10.3.2.1.1
            + self.pxe_x31  # Data sheet PDF: 10.3.2.1.2
            + self.pxe_x32  # Data sheet PDF: 10.3.2.1.3
            + self.pxe_x33  # Data sheet PDF: 10.3.2.1.4
            + self.generate_padding(22)
        )
        blob = self.add_checksum(blob)  # Data sheet PDF: 10.3.2.2
        blob += self.generate_g3_s5_configuration()
        blob += self.generate_padding(3946)

        return blob

######################################################################


# Set argparse Arguments
parser = argparse.ArgumentParser(
    description=(
        'Generate GBE firmware for 82579LM,82579V,i217LM,'
        'i217V,i218LM,i218V,i219LM,i219V'
    )
)

parser.add_argument(
    '--mac',
    type=is_mac_address,
    help='MAC Address',
    required=True
)
parser.add_argument(
    '--model',
    type=is_valid_model,
    help='Model',
    required=True
)
parser.add_argument(
    '--filename',
    help='Output filename',
    required=True
)
parser.add_argument(
    '--mobile',
    action='store_true',
    help='Is mobile for 82579LM or 82579V.  Default False'
)
parser.add_argument(
    '--lan-switch',
    action='store_true',
    help=(
        'Is Lan switch for i217LM,i217V,i218LM,i218V,i219LM, or i219V.'
        '  Default False.'
    )
)
args = parser.parse_args()

######################################################################

if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
else:
    gbe_generator = GbeGenerate(
        mac=args.mac,
        model=args.model.lower(),
        file_name=args.filename,
        mobile=args.mobile,
        lan_switch=args.lan_switch
    )

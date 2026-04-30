# Copy this file to CIRCUITPY/boot.py with firmware/hid/code.py to expose a
# vendor-defined HID interface for kde-serial-keylock.
#
# The existing firmware/code.py serial implementation is intentionally left
# unchanged. This HID firmware is an alternate deployment option.

import usb_hid
from usb_hid import Device

REPORT_ID = 1
REPORT_PAYLOAD_SIZE = 127  # host report size is report ID + this payload = 128 bytes

KEYLOCK_HID = Device(
    report_descriptor=bytes(
        (
            0x06,
            0x00,
            0xFF,  # Usage Page (Vendor Defined 0xFF00)
            0x09,
            0x01,  # Usage (0x01)
            0xA1,
            0x01,  # Collection (Application)
            0x85,
            REPORT_ID,  # Report ID
            0x15,
            0x00,  # Logical Minimum (0)
            0x26,
            0xFF,
            0x00,  # Logical Maximum (255)
            0x75,
            0x08,  # Report Size (8 bits)
            0x95,
            REPORT_PAYLOAD_SIZE,  # Report Count
            0x09,
            0x02,  # Usage (host-to-token line report)
            0x91,
            0x02,  # Output (Data, Variable, Absolute)
            0x95,
            REPORT_PAYLOAD_SIZE,  # Report Count
            0x09,
            0x03,  # Usage (token-to-host line report)
            0x81,
            0x02,  # Input (Data, Variable, Absolute)
            0xC0,  # End Collection
        )
    ),
    usage_page=0xFF00,
    usage=0x01,
    report_ids=(REPORT_ID,),
    in_report_lengths=(REPORT_PAYLOAD_SIZE,),
    out_report_lengths=(REPORT_PAYLOAD_SIZE,),
)

usb_hid.enable((KEYLOCK_HID,))

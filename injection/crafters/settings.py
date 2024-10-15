"""Contains global settings such as Default Parameters"""

# Global Settings
# ----------------
MAX_UBYTE = 2**8 - 1
MAX_USHORT = 2**16 - 1
MAX_FRAME_LEN = 2346
MAX_INFO_ELT_LEN = 255
MAX_INFO_ELT_NUM = 13

# Default Parameters
# -------------------

# -----------
# MAC_HEADER
# -----------
DA = "ff:ff:ff:ff:ff:ff"
SA = "00:1A:2B:3C:4D:5E"
BSSID = "00:1A:2B:3C:4D:5E"
FOFFSET = 0
SNUMBER = 0

# ------------
# BEACON_BODY
# ------------
TIMESTAMP = 42
INTERVAL = 100
CAPABILITY = "ESS+privacy"
SSID = "default"
MAX_SSID_LEN = 32
LONG_SSID_LEN = 253
RATES = [12, 18, 24, 36, 48, 72, 96, 108]

# -----------
# BEACON_EXT
# -----------
FH_SET = [
    500,  # Dwell Time
    1,  # Hop Set
    2,  # Hop Pattern
    0,  # Hop Index
]
DS_SET = 6  # Current Channel
CF_SET = [
    1,  # CFP Count
    2,  # CFP Period
    500,  # CFP Max Duration
    0,  # CFP Duration Remaining
]
IBSS = 0  # ATIM Window
TIM = [
    0,  # DTIM Count
    1,  # DTIM Period
    0,  # Bitmap Control
]
TIM_BITMAP = b"\x00"  # Partial Virtual Bitmap
COUNTRY_STRING = "DE"  # Country String
COUNTRY_CT = [
    1,  # First Channel Number
    13,  # Number of Channels
    20,  # Max Transmit Power
]
POWER_CONSTRAINT = 0  # Local Power Constraint
CSA = [
    0,  # Channel Switch Mode
    11,  # New Channel Number
    1,  # Channel Switch Count
]
QUIET = [
    1,  # Quiet Count
    2,  # Quiet Period
    100,  # Quiet Duration
    0,  # Quiet Offset
]
TPC_REPORT = [20, 0]  # Transmit Power, Link Margin
ERP = [
    0,  # Non-ERP Present
    0,  # Use Protection
    0,  # Barker Preamble
    0,  # Reserved
]
ERATES = [2, 4, 11, 22]
RSN_INFO = (
    b"\x01\x00"  # Version
    b"\x00\x0f\xac\x04"  # Group Cipher Suite
    b"\x01\x00"  # Pairwise Cipher Suite Count
    b"\x00\x0f\xac\x04"  # AES
    b"\x01\x00"  # Authentication Suite Count
    b"\x00\x0f\xac\x02"  # PSK
    b"\x00\x00"  # RSN Capabilities
)
RSN_INFO_EXT = (
    b"\x01\x00"  # Version
    b"\x00\x0f\xac\x04"  # Group Cipher Suite
    b"\x02\x00"  # Pairwise Cipher Suite Count
    b"\x00\x0f\xac\x04"  # AES
    b"\x00\x0f\xac\x05"  # WEP-104
    b"\x02\x00"  # Authentication Suite Count
    b"\x00\x0f\xac\x02"  # PSK
    b"\x01\x02\x0a\x0b"  # Vendor-specific
    b"\x00\x00"  # RSN Capabilities
    b"\x02\x00"  # PMK Count
    b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0"  # PMK List
    b"\xff"
)

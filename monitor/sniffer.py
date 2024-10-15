"""Provides functionality to sniff and analyze 802.11 frames.

Supports two modes: Synchronous and Asynchronous.
"""

from common import *
from scapy.layers.dot11 import sniff
from scapy.sendrecv import AsyncSniffer
from rich.live import Live
from rich.table import Table
from rich.console import Console
from io import TextIOWrapper
import sys
import re


# 802.11 Management Frame Subtypes
__MGMT_FRAMES = {
    0: "AssoReq",
    1: "AssoRes",
    2: "ReassoReq",
    3: "ReassoRes",
    4: "ProbeReq",
    5: "ProbeRes",
    6: "TimingAd",
    7: "Reserved",
    8: "Beacon",
    9: "ATIM",
    10: "Disasso",
    11: "Auth",
    12: "Deauth",
    13: "Action",
    14: "NACK",
    15: "Reserved",
}


def subtype_filter(*subtypes: str) -> Callable[..., bool]:
    """Returns a function that filters all the frames with
    specified subtypes.

    Args:
        *subtypes (str): Subtypes, which filtered frames share.

    Returns:
        Callable[..., bool]: A function that gets a `Packet` object as
            parameter and returns `True` if packet fulfills filter conditions.
    """

    subtype_values = []
    for subtype in subtypes:
        try:
            subtype_value = int(subtype)
            if subtype_value not in __MGMT_FRAMES:
                print(
                    f"Invalid subtype. Subtype must be between 0 and 15.",
                    file=sys.stderr,
                )
                exit(1)
            subtype_values.append(subtype_value)
        except ValueError:
            print(
                f"Invalid subtype format. Subtype must be an integer.", file=sys.stderr
            )
            exit(1)

    def filter(packet: Packet):
        if not packet.haslayer(Dot11):
            return False

        if packet.type == 0 and packet.subtype in subtype_values:
            return True
        return False

    return filter


def ssid_filter(*ssids: str) -> Callable[..., bool]:
    """Returns a function that filters all the frames with
    specified SSIDs.

    Args:
        *ssids (str): SSIDs, which filtered frames share.

    Returns:
        Callable[..., bool]: A function that gets a `Packet` object as
            parameter and returns `True` if packet fulfills filter conditions.
    """

    def filter(packet: Packet):
        if not packet.haslayer(Dot11):
            return False

        if packet.type == 0:
            client_ssid = ""
            try:
                client_ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
            except Exception:
                pass
            if client_ssid in ssids:
                return True
        return False

    return filter


def mac_filter(address_type: str, mac: str) -> Callable[..., bool]:
    """Returns a function that filters all the frames with
    the specified MAC address.

    Args:
        address_type (str): MAC address type. Available options:
            "addr1", "addr2", "addr3", "addr4" as defined in 802.11 MAC Header
        mac (str): MAC address, which filtered frames share.

    Returns:
        Callable[..., bool]: A function that gets a `Packet` object as
            parameter and returns `True` if packet fulfills filter conditions.
    """
    address_types = ["addr1", "addr2", "addr3", "addr4"]
    if address_type not in address_types:
        print(
            f"Invalid MAC Address type. Please provide a valid type: {address_types}",
            file=sys.stderr,
        )
        exit(1)

    # Check if MAC is valid
    mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if not re.match(mac_pattern, mac):
        print("Invalid MAC Address format.", file=sys.stderr)
        exit(1)

    def filter(packet: Packet):
        if not packet.haslayer(Dot11):
            return False

        if packet.type == 0:
            address = getattr(packet, address_type, None)
            if address == mac.lower():
                return True
        return False

    return filter


def combined_filter(*filters: Callable[..., bool]) -> Callable[..., bool]:
    """Returns a function that combines multiple packet filters.

    Args:
        *filters (Callable[..., bool]): A variable number of packet filters.

    Returns:
        Callable[..., bool]: A function that gets a `Packet` object as
            parameter and returns `True` if packet fulfills filter conditions.
    """

    def filter(packet: Packet):
        if not packet.haslayer(Dot11):
            return False
        for filter in filters:
            if not filter(packet):
                return False
        return True

    return filter


# Filter Functions and their arg count
# -1 indicates variable amount of args
FILTERS = {
    "subtype_filter": (subtype_filter, -1),
    "ssid_filter": (ssid_filter, -1),
    "mac_filter": (mac_filter, 2),
}


def __update_table(table: Table, row: List[str]):
    """Updates the generated table dynamically.

    A helper function that is used in table output mode.

    Args:
        address_type (str): MAC address type. Available options:
            "addr1", "addr2", "addr3", "addr4" as defined in 802.11 MAC Header
        mac (str): MAC address, which filtered frames share.

    Returns:
        Callable[..., bool]: A function that gets a `Packet` object as
            parameter and returns `True` if packet fulfills filter conditions.
    """
    l1, l2, l3, l4, l5 = (table.columns[i]._cells for i in range(5))
    rows = list(list(t) for t in zip(l1, l2, l3, l4, l5))
    try:
        index = rows.index(row[:5])  # type: ignore
        old_count = int(table.columns[-1]._cells[index])  # type: ignore
        table.columns[-1]._cells[index] = str(old_count + 1)
        table.columns[5]._cells[index] = row[5]
    except ValueError:
        table.add_row(*row)


def __callback_stdout(curr_channel: List[int]) -> Callable[..., None]:
    """Returns a function that prints the packet info to stdout.

    Args:
        curr_channel (List[int]): A list that holds the current channel
            iface is operating on.

    Returns:
        Callable[..., None]: A function that gets a `Packet` object as
            parameter and prints the packet info to stdout.
    """

    def callback(packet: Packet):
        if not packet.haslayer(Dot11):
            return

        if packet.type == 0 and packet.subtype in __MGMT_FRAMES:
            print("\n" + f"Channel {curr_channel[0]} " + packet.summary() + "\n")

    return callback


def __callback_table(table: Table, curr_channel: List[int]) -> Callable[..., None]:
    """Returns a function that prints the packet info in a
    dynamically generated table.

    Args:
        table (Table): A `Table` object.
        curr_channel (List[int]): A list that holds the current channel
            iface is operating on.

    Returns:
        Callable[..., None]: A function that gets a `Packet` object as
            parameter and prints the packet info in a table.
    """

    def callback(packet: Packet):
        if not (packet.haslayer(RadioTap) and packet.haslayer(Dot11)):
            return

        rssi = packet[RadioTap].dBm_AntSignal
        if rssi is None:
            rssi = ""

        if packet.type == 0 and packet.subtype in __MGMT_FRAMES:
            subtype = __MGMT_FRAMES[packet.subtype]
            src = packet.addr2
            dst = packet.addr1
            ssid = ""
            try:
                ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
            except Exception:
                pass

            row = [str(curr_channel[0]), subtype, src, dst, ssid, str(rssi), "1"]
            __update_table(table, row)

    return callback


def __callback_csv(file: TextIOWrapper, curr_channel: List[int]) -> Callable[..., None]:
    """Returns a function that writes the packet info to a csv file.

    Args:
        file (TextIOWrapper): A `Table` object.
        curr_channel (List[int]): A list that holds the current channel
            iface is operating on.

    Returns:
        Callable[..., None]: A function that gets a `Packet` object as
            parameter and writes the packet info to a csv file.
    """

    def callback(packet: Packet):
        if not (packet.haslayer(RadioTap) and packet.haslayer(Dot11)):
            return
        rssi = packet[RadioTap].dBm_AntSignal
        srssi = ""
        direction = "tx"
        if rssi:
            srssi = f"{rssi}dBm"
            direction = "rx"

        if packet.type == 0 and packet.subtype in __MGMT_FRAMES:
            subtype = __MGMT_FRAMES[packet.subtype]
            src = packet.addr2
            dst = packet.addr1
            ssid = ""
            try:
                ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
            except Exception:
                pass
            file.write(
                f'channel={curr_channel[0]},timestamp={packet.time},subtype="{subtype}",direction={direction},'
                f'source_address="{src}",destination_address="{dst}",ssid="{ssid}",rssi="{srssi}"\n'
            )

    return callback


def sniff_to_stdout(
    mode: str,
    iface: str,
    timeout: float,
    curr_channel: List[int],
    filter: Optional[Callable[..., bool]] = None,
) -> Optional[AsyncSniffer]:
    """Sniffs 802.11 packets and prints the packet info to stdout.

    Args:
        mode (str): Execution mode. `sync` for synchronous and `async`
            for asynchronous sniffing.
        iface (str): Name of the interface.
        timeout (float): Execution duration in seconds.
        curr_channel (List[int]): A list that holds the current channel
            iface is operating on.
        filter (Optional[Callable[..., bool]]): An optional function that
            gets a `Packet` object as parameter and returns `True` if packet
            fulfills filter conditions.

    Returns:
        Optional[AsyncSniffer]: An optional `AsyncSniffer` thread.
    """
    if mode == "sync":
        sniff(
            iface=iface,
            prn=__callback_stdout(curr_channel),
            timeout=timeout,
            lfilter=filter,
        )
        return None
    elif mode == "async":
        try:
            sniffer_thread = AsyncSniffer(
                iface=iface,
                prn=__callback_stdout(curr_channel),
                timeout=timeout,
                lfilter=filter,
            )
            sniffer_thread.start()
            return sniffer_thread
        except Exception as e:
            print(f"Failed to start SnifferThread: {e}", file=sys.stderr)
            exit(1)
    print("Unrecognized mode. Please provide sync or async", file=sys.stderr)
    exit(1)


def sniff_to_table(
    mode: str,
    iface: str,
    timeout: float,
    curr_channel: List[int],
    filter: Optional[Callable[..., bool]] = None,
) -> Optional[Tuple[AsyncSniffer, Live]]:
    """Sniffs 802.11 packets and prints the packet info in a
    dynamically generated table.

    Args:
        mode (str): Execution mode. `sync` for synchronous and `async`
            for asynchronous sniffing.
        iface (str): Name of the interface.
        timeout (float): Execution duration in seconds.
        curr_channel (List[int]): A list that holds the current channel
            iface is operating on.
        filter (Optional[Callable[..., bool]]): An optional function that
            gets a `Packet` object as parameter and returns `True` if packet
            fulfills filter conditions.

    Returns:
        Optional[Tuple[AsyncSniffer, Live]]: An optional tuple of `AsyncSniffer`
            thread and a `Live` object to manage the table.
    """
    console = Console(emoji=False)
    table = Table()
    table.add_column("Channel", width=10)
    table.add_column("Subtype", width=10)
    table.add_column("Source Address", width=20)
    table.add_column("Destination Address", width=20)
    table.add_column("SSID", width=50)
    table.add_column("RSSI (dBm)", width=10)
    table.add_column("Count", width=20)

    if mode == "sync":
        with Live(table, console=console):
            sniff(
                iface=iface,
                prn=__callback_table(table, curr_channel),
                timeout=timeout,
                lfilter=filter,
            )
        return None
    elif mode == "async":
        try:
            live = Live(table, console=console)
            live.start()
        except Exception as e:
            print(f"Failed to start Live: {e}", file=sys.stderr)
            exit(1)

        try:
            sniffer_thread = AsyncSniffer(
                iface=iface,
                prn=__callback_table(table, curr_channel),
                timeout=timeout,
                lfilter=filter,
            )
            sniffer_thread.start()
            return sniffer_thread, live
        except Exception as e:
            print(f"Failed to start either SnifferThread or Live: {e}", file=sys.stderr)
            live.stop()
            exit(1)
    print("Unrecognized mode. Please provide sync or async", file=sys.stderr)
    exit(1)


def sniff_to_csv(
    output: str,
    mode: str,
    iface: str,
    timeout: float,
    curr_channel: List[int],
    filter: Optional[Callable[..., bool]] = None,
) -> Optional[Tuple[AsyncSniffer, TextIOWrapper]]:
    """Sniffs 802.11 packets and writes the packet info to a csv file.

    Args:
        output (str): Name of the csv file with the file extension ".csv".
        mode (str): Execution mode. `sync` for synchronous and `async`
            for asynchronous sniffing.
        iface (str): Name of the interface.
        timeout (float): Execution duration in seconds.
        curr_channel (List[int]): A list that holds the current channel
            iface is operating on.
        filter (Optional[Callable[..., bool]]): An optional function that
            gets a `Packet` object as parameter and returns `True` if packet
            fulfills filter conditions.

    Returns:
        Optional[Tuple[AsyncSniffer, TextIOWrapper]]: An optional tuple
            of `AsyncSniffer` thread and a `TextIOWrapper` object that
            points to the file.
    """
    if mode == "sync":
        with open(output, mode="w", newline="") as file:
            sniff(
                iface=iface,
                prn=__callback_csv(file, curr_channel),
                timeout=timeout,
                lfilter=filter,
            )
        return None
    elif mode == "async":
        try:
            file = open(output, mode="w", newline="")
        except Exception as e:
            print(f"Failed to open the file: {e}", file=sys.stderr)
            exit(1)

        try:
            sniffer_thread = AsyncSniffer(
                iface=iface,
                prn=__callback_csv(file, curr_channel),
                timeout=timeout,
                lfilter=filter,
            )
            sniffer_thread.start()
            return sniffer_thread, file
        except Exception as e:
            print(f"Failed to start SnifferThread: {e}", file=sys.stderr)
            file.close()
            exit(1)
    print("Unrecognized mode. Please provide sync or async", file=sys.stderr)
    exit(1)

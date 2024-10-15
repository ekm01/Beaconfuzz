"""Includes functions for putting the Wi-fi interface into monitor
mode.

Utilizes external network tools such as 'iw', 'iwconfig' and
'airmon-ng'.
"""

import subprocess
import sys
import re
import time
from typing import Set
from common import List, Tuple, Optional


def get_phy(iface: str) -> str:
    """Gets the name of the PHY.

    Args:
        iface (str): Name of the interface.

    Returns:
        str: Name of the PHY.
    """
    phy_path = f"/sys/class/net/{iface}/phy80211/name"
    try:
        cmd = subprocess.run(["cat", phy_path], capture_output=True, text=True)
        if cmd.returncode != 0:
            print("Interface not found or command failed.", file=sys.stderr)
            exit(cmd.returncode)
        phy = cmd.stdout.strip()
        return phy
    except Exception as e:
        print(f"Failed to get phy name: {e}", file=sys.stderr)
        exit(1)


def get_channels(phy: str) -> Set[int]:
    """Gets all the supported channels.

    Args:
        phy (str): Name of the PHY.

    Returns:
        Set[int]: A set of channel numbers.
    """
    command = (
        f"iw phy {phy} channels | awk -F'[][]' '$2 && $3 !~ /disabled/ {{print $2}}'"
    )
    try:
        cmd = subprocess.run(command, shell=True, capture_output=True, text=True)
        if cmd.returncode != 0:
            print("PHY not found or command failed.", file=sys.stderr)
            exit(cmd.returncode)
        channels = cmd.stdout.split()
        channel_set = {int(channel) for channel in channels}
        return channel_set
    except Exception as e:
        print(f"Failed to get supported channels: {e}", file=sys.stderr)
        exit(1)


def is_monitor_on(iface: str) -> bool:
    """Checks if the interface is in monitor mode.

    Args:
        iface (str): Name of the interface.

    Returns:
        bool: 'True', if the interface is already in monitor mode.
    """
    try:
        cmd = subprocess.run(["iwconfig", iface], capture_output=True, text=True)
        if cmd.returncode != 0:
            print("Interface not found or command failed.", file=sys.stderr)
            exit(cmd.returncode)
        if "Mode:Monitor" in cmd.stdout:
            return True
        return False
    except Exception as e:
        print(f"Failed to check if monitor mode is on: {e}", file=sys.stderr)
        exit(1)


def stop_procs(naive: bool, verbose: bool = True) -> List[str]:
    """Stops interfering processes.

    Args:
        naive (bool): If 'True', stops only NetworkManager and
            wpa_supplicant, otherwise stops all of them.
        verbose (bool): If `True`, log the process. By default, `True`

    Returns:
        List[str]: A list of stopped process names.
    """
    if naive:
        procs = ["NetworkManager", "wpa_supplicant"]
        if verbose:
            print("Killing the following processes: NetworkManager, wpa_supplicant")
        for process in procs:
            try:
                cmd = subprocess.run(
                    ["systemctl", "stop", process],
                    capture_output=True,
                    text=True,
                )
                if cmd.returncode != 0:
                    print("Command failed.", file=sys.stderr)
                    exit(cmd.returncode)
            except Exception as e:
                print(f"Failed to kill process {process}: {e}", file=sys.stderr)
                exit(1)
        return procs

    try:
        if verbose:
            print(
                "Searching for processes that may interfere with the monitor mode: airmon-ng check"
            )
        cmd = subprocess.run(["airmon-ng", "check"], capture_output=True, text=True)
        if cmd.returncode != 0:
            print("Command failed.", file=sys.stderr)
            exit(cmd.returncode)

        interfering_procs = []
        for line in cmd.stdout.split("\n"):
            pattern = re.search(r"^\s*\d+\s+(\S+)", line)
            if pattern:
                name = pattern.group(1)
                if name not in interfering_procs:
                    interfering_procs.append(name)

        if verbose:
            print(
                "Killing the interfering processes via systemctl: airmon-ng check kill"
            )
        cmd = subprocess.run(
            ["airmon-ng", "check", "kill"], capture_output=True, text=True
        )
        if cmd.returncode != 0:
            print("Command failed.", file=sys.stderr)
            exit(cmd.returncode)

        return interfering_procs

    except Exception as e:
        print(f"Failed to kill interfering processes: {e}", file=sys.stderr)
        exit(1)


def restart_procs(procs: List[str], verbose: bool = True) -> None:
    """Restarts stopped processes.

    Args:
        procs (List[str]): A list of stopped process names.
        verbose (bool): If `True`, log the process. By default, `True`
    """
    if not procs:
        print("No processes found to be restarted", file=sys.stderr)
        exit(0)

    if verbose:
        print("Restarting processes: ", end="")
        print(procs)
    for process in procs:
        try:
            cmd = subprocess.run(["systemctl", "restart", process], check=True)
            if cmd.returncode != 0:
                print("Command failed.", file=sys.stderr)
                exit(cmd.returncode)
        except Exception as e:
            print(f"Failed to restart process {process}: {e}", file=sys.stderr)
            exit(1)


def change_channel(
    iface: str, channel: int, bandwidth: Optional[int] = None, verbose: bool = True
) -> None:
    """Changes Wi-fi channel.

    Args:
        iface (str): Name of the interface.
        channel (int): Channel number.
        bandwidth (Optional[int]): Optional bandwidth of the channel.
        verbose (bool): If `True`, log the process. By default, `True`
    """
    if verbose:
        print(
            f"Changing channel to {channel}: iw dev {iface} set channel {str(channel)}"
        )
    try:
        cmd_list = ["iw", "dev", iface, "set", "channel", str(channel)]
        if bandwidth:
            sbandwith = str(bandwidth) + "MHz"
            cmd_list.append(sbandwith)

        cmd = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
        if cmd.returncode != 0:
            print("Command failed.", file=sys.stderr)
            exit(cmd.returncode)
    except Exception as e:
        # Error Code 234 refers to invalid channel
        if "234" in f"{e}":
            exit(1)


def set_monitor(
    iface: str,
    mode: str,
    naive: bool,
    channel: int = 6,
    bandwidth: Optional[int] = None,
    verbose: bool = True,
) -> Tuple[str, List[str]]:
    """Puts Wi-fi interface into monitor mode.

    Args:
        iface (str): Name of the interface.
        mode (str): External network tool to be used. Available options:
            'iw' and 'airmon-ng'.
        naive (bool): If 'True', stops only NetworkManager and
            wpa_supplicant, otherwise stops all of them.
        channel (int): Channel number.
        bandwidth (Optional[int]): Optional bandwidth of the channel.
        verbose (bool): If `True`, log the process. By default, `True`
    """
    if is_monitor_on(iface):
        print("Interface is already in monitor mode", file=sys.stderr)
        exit(0)

    interfering_procs = stop_procs(naive, verbose)

    # Make sure all the processes are killed
    time.sleep(2)

    try:
        if mode == "airmon-ng":
            if verbose:
                print(f"Setting interface to monitor mode: airmon-ng start {iface}")
            cmd = subprocess.run(
                ["airmon-ng", "start", iface], capture_output=True, text=True
            )
            if cmd.returncode != 0:
                print("Command failed.", file=sys.stderr)
                exit(cmd.returncode)
        elif mode == "iw":
            if verbose:
                print(
                    f"Setting interface to monitor mode: iw dev {iface} interface add {iface}mon type monitor"
                )
            cmd = subprocess.run(
                [
                    "iw",
                    "dev",
                    iface,
                    "interface",
                    "add",
                    iface + "mon",
                    "type",
                    "monitor",
                ],
                capture_output=True,
                text=True,
            )
            if cmd.returncode != 0:
                print("Command failed.", file=sys.stderr)
                exit(cmd.returncode)

            if verbose:
                print(f"Setting interface up: ip link set up {iface}mon")
            cmd = subprocess.run(
                ["ip", "link", "set", "up", iface + "mon"],
                capture_output=True,
                text=True,
            )
            if cmd.returncode != 0:
                print("Command failed.", file=sys.stderr)
                exit(cmd.returncode)
        else:
            print(
                f"Unrecognized mode: {mode}\n Available modes: airmon-ng, iw",
                file=sys.stderr,
            )
            exit(1)
    except Exception as e:
        print(f"Failed to start monitor: {e}", file=sys.stderr)
        exit(1)

    change_channel(iface + "mon", channel, bandwidth, verbose)
    return iface + "mon", interfering_procs


def unset_monitor(
    iface: str, mode: str, procs: List[str], verbose: bool = True
) -> None:
    """Sets the Wi-Fi interface in monitor mode to be inactive.

    Args:
        iface (str): Name of the interface.
        mode (str): External network tool to be used. Available options:
            'iw' and 'airmon-ng'.
        procs (List[str]): A list of stopped process names.
        verbose (bool): If `True`, log the process. By default, `True`
    """
    if not is_monitor_on(iface):
        print("Interface is not in monitor mode", file=sys.stderr)
        exit(0)

    try:
        if mode == "airmon-ng":
            if verbose:
                print(f"Unsetting monitor mode: airmon-ng stop {iface}")
            cmd = subprocess.run(
                ["airmon-ng", "stop", iface], capture_output=True, text=True
            )
            if cmd.returncode != 0:
                print("Command failed.", file=sys.stderr)
                exit(cmd.returncode)
        elif mode == "iw":
            if verbose:
                print(f"Unsetting monitor mode: ip link set down {iface}")
            cmd = subprocess.run(
                ["ip", "link", "set", "down", iface], capture_output=True, text=True
            )
            if cmd.returncode != 0:
                print("Command failed.", file=sys.stderr)
                exit(cmd.returncode)
            if verbose:
                print(f"Run to delete the virtual interface: sudo iw dev {iface} del")
        else:
            print(
                f"Unrecognized mode: {mode}\n Available modes: airmon-ng, iw",
                file=sys.stderr,
            )
            exit(1)
    except Exception as e:
        print(f"Failed to unset monitor mode: {e}", file=sys.stderr)

    restart_procs(procs, verbose)

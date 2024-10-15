"""Provides functionality to send 802.11 Beacon frames based on
the parameters in a user-defined `config.ini` file.

Supports two modes: Synchronous and Asynchronous. For the
Synchronous mode, the sender will execute blocking. As for
the Asynchronous mode, an additional daemon thread will be spawned.
"""

from injection.crafters.config_crafter import *
from scapy.layers.dot11 import sendp
import sys
from threading import *
import itertools


def _extract_valid_beacon(
    beacon: Beacon | BeaconGenerator,
) -> Tuple[Beacon, Optional[BeaconGenerator]]:
    """Extracts a valid Beacon from a given Packet or Packet Iterator.

    Args:
        beacon (Beacon | BeaconGenerator): A beacon frame or
            a beacon generator.

    Returns:
        Tuple[Beacon, Optional[BeaconGenerator]]: A valid beacon frame
            and an optional generator.

    Raises:
        TypeError: If `beacon` is not a Packet or Packet Iterator.
        ValueError: If `beacon` has the wrong format/lacks specific
            layers.
    """
    packet = beacon
    gen = None
    if not isinstance(packet, Beacon):
        try:
            copy1, copy2 = itertools.tee(beacon)
            packet = next(copy1)
            gen = copy2
            if not isinstance(packet, Beacon):
                raise TypeError()
        except TypeError:
            print(
                "Unexpected beacon parameter: Please provide a Packet or Packet Iterator object",
                file=sys.stderr,
            )
            exit(1)
        except StopIteration:
            print("Provided Packet Iterator is empty", file=sys.stderr)
            exit(1)

    if (
        not packet.haslayer(RadioTap)
        or not packet.haslayer(Dot11FCS)
        or not packet.haslayer(Dot11Beacon)
    ):
        raise ValueError(
            "Unexpected beacon format: It should contain the layers RadioTap, Dot11FCS and Dot11Beacon"
        )
    return packet, gen  # type: ignore


class ConfigSender:
    """Parses sending parameters specified in `config.ini`
    and sends a Beacon frame.

    Attributes:
        __config_path (str): Path to the config file.
        __iface (str): Name of the interface.
        __config (ConfigParser): Stores string values of configurations.
    """

    def __init__(self, config_path: str, iface: str):
        """Parses the configurations.

        Args:
            config_path (str): Path to the config file.
            iface (str): Name of the interface.
        """
        self.__iface = iface
        # Read INI file
        self.__config_path = config_path
        self.__config: ConfigParser = ConfigParser()
        self.__config.read(config_path)

    def send_sync(
        self,
        beacon: Optional[Beacon | BeaconGenerator] = None,
        show=False,
        verbose=True,
    ) -> None:
        """Sends Beacon frames synchronously.

        Args:
            beacon (Optional[Beacon | BeaconGenerator]): A beacon frame or
                a beacon generator. If not provided, the beacon frame
                is crafted via `ConfigCrafter`.
            show (bool): If `True`, print the packet to be sent. By
                default, `False`
            verbose (bool): If `True`, log the sending process. By
                default, `True`

        Raises:
            SectionNotFoundError: If the section `Packet Send` cannot be found.
            TypeError: Raised by `_extract_valid_beacon`
            ValueError: Raised by `_extract_valid_beacon`
        """
        section = "Packet Send"
        count, count_defined = None, False
        if self.__config.has_option(section, "count"):
            count = int(self.__config[section]["count"])
            count_defined = True

        if beacon is None:
            beacon = ConfigCrafter(self.__config_path).generate_from_config(count=count)

        packet, gen = _extract_valid_beacon(beacon)
        if not self.__config.has_section(section):
            raise SectionNotFoundError(section)

        # Beacon Interval is given in Target Beacon Transmission Time (TBTT)
        # 1 TU = 1024 microseconds
        inter = (
            float(self.__config[section]["inter"])
            if self.__config.has_option(section, "inter")
            else float(self.__config["Beacon Body"]["Interval"]) * 1024 * (10**-6)
        )

        if show:
            packet.show2()

        if count_defined:
            sendp(
                packet if gen is None else (beacon for beacon in gen),
                iface=self.__iface,
                count=int(self.__config[section]["count"]),
                inter=inter,
                verbose=verbose,
            )
        else:
            sendp(
                packet if gen is None else (beacon for beacon in gen),
                iface=self.__iface,
                inter=inter,
                loop=1,
                verbose=verbose,
            )


class ConfigSenderThread(Thread):
    """Extends `threading.Thread` to send Beacon Frames asynchronously.

    Attributes:
        __config_sender (ConfigSender): A `ConfigSender` object.
        beacon (Optional[Beacon | BeaconGenerator]): A beacon frame or
                a beacon generator. If not provided, the beacon frame
                is crafted via `ConfigCrafter`.
        show (bool): If `True`, print the packet to be sent. By
            default, `False`
        verbose (bool): If `True`, log the sending process. By
            default, `True`
        exception (Optional[Exception]): An optional `Exception`
            occurred while running the `ConfigSenderThread`
        daemon (bool): Indicates if the Thread is a daemon or not.

    All the other attributes are by default `threading.Thread`
    attributes.
    """

    def __init__(
        self,
        config_path: str,
        iface: str,
        beacon: Optional[Beacon | BeaconGenerator] = None,
        show=False,
        verbose=True,
    ) -> None:
        """Initializes a `ConfigSenderThread` object.

        Args:
            config_path (str): Path to the config file.
            iface (str): Name of the interface.
            beacon (Optional[Beacon | BeaconGenerator]): A beacon frame or
                a beacon generator. If not provided, the beacon frame
                is crafted via `ConfigCrafter`.
            show (bool): If `True`, print the packet to be sent. By
                default, `False`
            verbose (bool): If `True`, log the sending process. By
                default, `True`
        """
        self.__config_sender = ConfigSender(config_path, iface)
        super().__init__()
        self.beacon = beacon
        self.show = show
        self.verbose = verbose
        self.exception: Optional[Exception] = None
        self.daemon = True

    def run(self) -> None:
        """Runs a `ConfigSenderThread`.

        Raises:
            SectionNotFoundError: Raised by `send_sync`.
        """
        try:
            self.__config_sender.send_sync(
                beacon=self.beacon, show=self.show, verbose=self.verbose
            )
        except Exception as e:
            self.exception = e

    def get_exception(self) -> Optional[Exception]:
        """Method to retrieve the currently raised `Exception`.

        Returns:
            Optional[Exception]: An optional exception object.
        """
        return self.exception


def send_sync_from_config(
    config_path: str,
    iface: str,
    beacon: Optional[Beacon | BeaconGenerator] = None,
    show=False,
    verbose=True,
) -> None:
    """Sends Beacon frames synchronously from config file all in one.

    Args:
        config_path (str): Path to the config file.
        iface (str): Name of the interface.
        beacon (Optional[Beacon | BeaconGenerator]): A beacon frame or
                a beacon generator. If not provided, the beacon frame
                is crafted via `ConfigCrafter`.
        show (bool): If `True`, print the packet to be sent. By
            default, `False`
        verbose (bool): If `True`, log the sending process. By
            default, `True`

    Raises:
        SectionNotFoundError: Raised by `send_sync`.
    """
    ConfigSender(config_path, iface).send_sync(beacon, show, verbose)


def send_async_from_config(
    config_path: str,
    iface: str,
    beacon: Optional[Beacon | BeaconGenerator] = None,
    show=False,
    verbose=True,
) -> None:
    """Sends Beacon frames asynchronously from config file all in one.

    Args:
        config_path (str): Path to the config file.
        iface (str): Name of the interface.
        beacon (Optional[Beacon | BeaconGenerator]): A beacon frame or
                a beacon generator. If not provided, the beacon frame
                is crafted via `ConfigCrafter`.
        show (bool): If `True`, print the packet to be sent. By
            default, `False`
        verbose (bool): If `True`, log the sending process. By
            default, `True`

    Raises:
        SectionNotFoundError: Raised by `ConfigSenderThread.run`.
    """
    try:
        ConfigSenderThread(config_path, iface, beacon, show, verbose).start()
    except Exception as e:
        print(f"Failed to start ConfigSenderThread: {e}", file=sys.stderr)
        exit(1)

from typing import Union, Generator, Tuple, List, Optional, Callable, Any
from scapy.layers.dot11 import (
    Dot11,
    Dot11FCS,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltCountry,
    Dot11EltCountryConstraintTriplet,
    Packet,
    RadioTap,
    Dot11EltRates,
    Dot11EltDSSSet,
    Dot11EltERP,
)

BeaconLayer = Union[
    Dot11FCS,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltCountry,
    Dot11EltCountryConstraintTriplet,
    Packet,
    RadioTap,
    Dot11EltRates,
    Dot11EltDSSSet,
    Dot11EltERP,
]
Beacon = Packet
BeaconGenerator = Generator[Packet, None, None]

"""Provides functionality to craft 802.11 Beacon frame based on
the parameters in a user-defined `config.ini` file.
"""

from common import *
from configparser import ConfigParser
from injection.crafters.settings import *
import pycountry
import re
import struct


class SectionNotFoundError(Exception):
    """Raised when a section cannot be found in `config.ini`."""

    def __init__(self, section: str):
        self.section = section
        self.message = f"Section '{self.section}' not found in the configuration file."
        super().__init__(self.message)


class OptionNotFoundError(Exception):
    """Raised when an option cannot be found in a section."""

    def __init__(self, section: str, option: str):
        self.section = section
        self.option = option
        self.message = (
            f"Option '{self.option}' not found in the section '{self.section}'"
        )
        super().__init__(self.message)


class ConfigCrafter:
    """Parses field values of the layers specified in
    `config.ini` and crafts a Beacon frame.

    Attributes:
        __config (ConfigParser): Stores string values of configurations.

    If some field values are not found in `config.ini`,
    they are replaced with the default values.
    """

    def __init__(self, config_path: str):
        """Parses the configurations.

        Args:
            config_path (str): Path to the config file.
        """
        # Read INI file
        self.__config: ConfigParser = ConfigParser()
        self.__config.read(config_path)

    def craft_mac_header(self, sn: int = SNUMBER) -> BeaconLayer:
        """Crafts MAC Header and adds FCS based on `config.ini`.

        Returns:
            BeaconLayer: A layer that contains MAC info and FCS.

        Raises:
            SectionNotFoundError: If the section `MAC Header` cannot be found.
            OptionNotFoundError: If the options `SA` or `BSSID` cannot be found.
            ValueError: If `SNumber` is not between `0 (0x0)` and `4095 (0xFFF)`.
                If `FOffset` is not between `0 (0x0)` and `15 (0xF)`
        """
        section = "MAC Header"
        if not self.__config.has_section(section):
            raise SectionNotFoundError(section)

        dst = (
            DA
            if not self.__config.has_option(section, "DA")
            else self.__config[section]["DA"]
        )

        # Sequence Control
        fragment_offset = FOFFSET
        if self.__config.has_option(section, "FOffset"):
            sfo = self.__config[section]["FOffset"]
            fragment_offset = (
                int(sfo, 16) if sfo.strip().startswith(("0x", "0X")) else int(sfo)
            )

        sequence_number = sn
        if self.__config.has_option(section, "SNumber"):
            ssn = self.__config[section]["SNumber"]
            sequence_number = (
                int(ssn, 16) if ssn.strip().startswith(("0x", "0X")) else int(ssn)
            )

        if not (0x0 <= fragment_offset <= 0xF and 0x000 <= sequence_number <= 0xFFF):
            raise ValueError(
                "Invalid Sequence Control [FragmentOffset][Sequence Number].\n"
                "Expected: 0 <= Fragment Offset <= 0xF and 0 <= Sequence Number <= 0xFFF"
            )
        sequence_control = (sequence_number << 4) | fragment_offset

        try:
            return Dot11FCS(
                type=0,
                subtype=8,
                addr1=dst,
                addr2=self.__config[section]["SA"],
                addr3=self.__config[section]["BSSID"],
                SC=sequence_control,
            )
        except KeyError as e:
            raise OptionNotFoundError(section, e.args[0])

    def craft_body(self) -> BeaconLayer:
        """Crafts Frame Body based on `config.ini`.

        Returns:
            BeaconLayer: A layer that defines Beacon Body.

        Raises:
            SectionNotFoundError: If the section `Beacon Body` cannot be found.
            OptionNotFoundError: If the option `SSID` cannot be found.
        """
        section = "Beacon Body"
        if not self.__config.has_section(section):
            raise SectionNotFoundError(section)

        if not self.__config.has_option(section, "SSID"):
            raise OptionNotFoundError(section, "SSID")

        # Beacon Interval is given in Target Beacon Transmission Time (TBTT)
        # 1 TU = 1024 microseconds
        timestamp = TIMESTAMP
        if self.__config.has_option(section, "Timestamp"):
            stimestamp = self.__config[section]["Timestamp"]
            timestamp = (
                int(stimestamp, 16)
                if stimestamp.strip().startswith(("0x", "0X"))
                else int(stimestamp)
            )

        interval = INTERVAL
        if self.__config.has_option(section, "Interval"):
            sinterval = self.__config[section]["Interval"]
            interval = (
                int(sinterval, 16)
                if sinterval.strip().startswith(("0x", "0X"))
                else int(sinterval)
            )

        cap = (
            CAPABILITY
            if not self.__config.has_option(section, "Capability")
            else self.__config[section]["Capability"]
        )

        beacon_body = Dot11Beacon(
            timestamp=timestamp,
            beacon_interval=interval,
            cap=cap,
        )

        ssid = Dot11Elt(
            ID="SSID",
            info=self.__config[section]["SSID"],
        )

        # Rates are given in units of 0.5 Mbps
        rates = RATES
        if self.__config.has_option(section, "Rates"):
            rates = [
                (
                    int(rate, 16) * 2
                    if rate.strip().startswith(("0x", "0X"))
                    else int(rate) * 2
                )
                for rate in self.__config[section]["Rates"].split(",")
            ]
        supported_rates = Dot11EltRates(rates=rates)
        return beacon_body / ssid / supported_rates

    def __extract_rsn_params(self, sparams: str, length: int) -> bytes:
        """Extracts RSN parameters from a given string.

        Args:
            sparams (str): A string delimited by `,`.
            length (int): The length of each RSN parameter.

        Returns:
            bytes: RSN parameters converted to bytes and appended
                together in the given order.
        """
        params = b""
        for sparam in sparams.split(","):
            if sparam.strip().startswith(("0x", "0X")):
                s = sparam.strip()[2:].zfill(length)
                if len(s) == length:
                    params += bytes.fromhex(s)
        return params

    def __craft_rsn(self) -> Optional[BeaconLayer]:
        """Crafts RSN Information Element based on `config.ini`.

        RSN Info is given in a separate section unlike other
        Information Elements.

        Returns:
            Optional[BeaconLayer]: An optional layer that defines RSN.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """

        # Robust Security Network: Version, Group Cipher Suite, Pairwise Cipher Suite, Authentication Suite
        #                          RSN Capabilities, PMK Count, PMK List
        # Pairwise Cipher Suite: Pairwise Cipher Suite Count, Pairwise Cipher Suite
        # Authentication Suite: Authentication Suite Count, Authentication Suite
        section = "RSN Info"
        if not self.__config.has_section(section):
            return None

        version = RSN_INFO[:2]
        if self.__config.has_option(section, "Version"):
            sversion = self.__config[section]["Version"]
            version = struct.pack(
                "H",
                (
                    int(sversion, 16)
                    if sversion.strip().startswith(("0x", "0X"))
                    else int(sversion)
                ),
            )

        groupcs = RSN_INFO[2:6]
        if self.__config.has_option(section, "GroupCS"):
            if not self.__config[section]["GroupCS"].strip().startswith(("0x", "0X")):
                raise ValueError(
                    "Invalid RSN Group Cipher Suite: GroupCS is in hex and has to start with the prefix 0x or 0X."
                )
            groupcs = struct.pack("!I", int(self.__config[section]["GroupCS"], 16))

        pairwisecsc = RSN_INFO[6:8]
        if self.__config.has_option(section, "PairwiseCSC"):
            spairwisecsc = self.__config[section]["PairwiseCSC"]
            pairwisecsc = struct.pack(
                "H",
                (
                    int(spairwisecsc, 16)
                    if spairwisecsc.strip().startswith(("0x", "0X"))
                    else int(spairwisecsc)
                ),
            )

        pairwisecs = RSN_INFO[8:12]
        if self.__config.has_option(section, "PairwiseCS"):
            pairwisecs = self.__extract_rsn_params(
                self.__config[section]["PairwiseCS"], 8
            )

        akmcsc = RSN_INFO[12:14]
        if self.__config.has_option(section, "AKMCSC"):
            sakmcsc = self.__config[section]["AKMCSC"]
            akmcsc = struct.pack(
                "H",
                (
                    int(sakmcsc, 16)
                    if sakmcsc.strip().startswith(("0x", "0X"))
                    else int(sakmcsc)
                ),
            )

        akmcs = RSN_INFO[14:18]
        if self.__config.has_option(section, "AKMCS"):
            akmcs = self.__extract_rsn_params(self.__config[section]["AKMCS"], 8)

        rsncaps = RSN_INFO[18:20]
        if self.__config.has_option(section, "RSNCaps"):
            srsncaps = self.__config[section]["RSNCaps"]
            if not srsncaps.strip().startswith(("0x", "0X")):
                raise ValueError(
                    "Invalid RSN Capabilities: RSNCaps is in hex and has to start with the prefix 0x or 0X."
                )
            rsncaps = struct.pack("H", int(srsncaps, 16))

        params = version + groupcs + pairwisecsc + pairwisecs + akmcsc + akmcs + rsncaps

        if self.__config.has_option(section, "PMKC") and self.__config.has_option(
            section, "PMKL"
        ):
            spmkc = self.__config[section]["PMKC"]
            pmkc = struct.pack(
                "H",
                (
                    int(spmkc, 16)
                    if spmkc.strip().startswith(("0x", "0X"))
                    else int(spmkc)
                ),
            )

            pmkids = self.__extract_rsn_params(self.__config[section]["PMKL"], 32)
            params += pmkc + pmkids

        return Dot11Elt(
            ID=48,
            info=params,
        )

    def __convert_fhset_to_bytes(self, sfhset: str) -> bytes:
        """Converts FH Set parameters that are given as a string.

        Args:
            sfhset (str): A string delimited by `,`.

        Returns:
            bytes: FH Set parameters converted to bytes and appended
                together in the given order.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        fhset_params = sfhset.split(",")
        if len(fhset_params) > len(FH_SET):
            raise ValueError(
                "Too many parameters provided for FH Parameter Set.\n"
                "Expected: [Dwell Time][Hop Set][Hop Pattern][Hop Index]"
            )
        fhset = [
            int(param, 16) if param.strip().startswith(("0x", "0X")) else int(param)
            for param in fhset_params
        ]
        fhset.extend(FH_SET[len(fhset) :])
        return struct.pack("HBBB", fhset[0], fhset[1], fhset[2], fhset[3])

    def __convert_cfset_to_bytes(self, scfset: str) -> bytes:
        """Converts CF Set parameters that are given as a string.

        Args:
            scfset (str): A string delimited by `,`.

        Returns:
            bytes: CF Set parameters converted to bytes and appended
                together in the given order.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        cfset_params = scfset.split(",")
        if len(cfset_params) > len(CF_SET):
            raise ValueError(
                "Too many parameters provided for CF Parameter Set.\n"
                "Expected: [CFP Count][CFP Period][Max Duration][Duration Remaining]"
            )
        cfset = [
            int(param, 16) if param.strip().startswith(("0x", "0X")) else int(param)
            for param in cfset_params
        ]
        cfset.extend(CF_SET[len(cfset) :])
        return struct.pack("BBHH", cfset[0], cfset[1], cfset[2], cfset[3])

    def __convert_tim_to_bytes(self, stim: str) -> bytes:
        """Converts TIM parameters that are given as a string.

        Args:
            stim (str): A string delimited by `,`.

        Returns:
            bytes: TIM parameters converted to bytes and appended
                together in the given order.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        tim_params = stim.split(",")
        tim_length = len(TIM) + 1
        if len(tim_params) > tim_length:
            raise ValueError(
                "Too many parameters provided for TIM.\n"
                "Expected: [DTIM Count][DTIM Period][Bitmap Control][Partial Virtual Bitmap]"
            )
        count_period_bmc = [
            int(param, 16) if param.strip().startswith(("0x", "0X")) else int(param)
            for param in tim_params[:3]
        ]
        count_period_bmc.extend(TIM[len(count_period_bmc) :])
        bitmap = TIM_BITMAP
        if len(tim_params) == tim_length:
            sbitmap = tim_params[3].strip()
            if not sbitmap.startswith(("0x", "0X")):
                raise ValueError(
                    "Invalid Bitmap: Bitmap is in hex and has to start with the prefix 0x or 0X."
                )

            fill = len(sbitmap[2:]) + (len(sbitmap[2:]) % 2)
            bitmap = bytes.fromhex(sbitmap[2:].zfill(fill))

        format_string = "3s" + str(len(bitmap)) + "s"
        return struct.pack(format_string, bytes(count_period_bmc), bitmap)

    def __extract_constraints(self, sconstraint: str) -> Tuple[int, int, int]:
        """Extracts Country Constraint Triplet from a given string.

        Args:
            sconstraint (str): A string delimited by `;`.

        Returns:
            Tuple[int, int, int]: A tuple consisting of Country Constraint parameters
                as integers.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        sconstraint = sconstraint.strip()
        expected_format = r"\[\s*(0[xX][0-9a-fA-F]+|[0-9]+)\s*;\s*(0[xX][0-9a-fA-F]+|[0-9]+)\s*;\s*(0[xX][0-9a-fA-F]+|[0-9]+)\s*\]"
        if not re.fullmatch(expected_format, sconstraint):
            raise ValueError(
                "Invalid Country Constraint Triplet\n"
                "Expected: [First Channel Number; Number of Channels; Maximum Transmit Power]"
                " with params as integers either in decimal or in hex starting with the prefix 0x or 0X"
            )
        constraint_params = [
            int(param, 16) if param.strip().startswith(("0x", "0X")) else int(param)
            for param in sconstraint[1:-1].split(";")
        ]
        return constraint_params[0], constraint_params[1], constraint_params[2]

    def __extract_country_info(self, scountry: str) -> Tuple[bytes, List[BeaconLayer]]:
        """Extracts Country Information parameters from a given string.

        Args:
            scountry (str): A string delimited by `,`.

        Returns:
            Tuple[bytes, List[BeaconLayer]]: A tuple consisting of Country
                Code as bytes and a layer that defines Country Constraint
                Triplet.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        country_params = scountry.split(",")
        min_params_len = 2
        # Alpha-2 or Alpha-3 Codes
        if not pycountry.countries.get(
            alpha_2=country_params[0]
        ) and not pycountry.countries.get(alpha_3=country_params[0]):
            raise ValueError(
                "Invalid Country Code: Country Code has to be in format ISO Alpha-2/Alpha-3"
            )

        country_code = country_params[0].upper().encode("utf-8")
        constraints = [
            Dot11EltCountryConstraintTriplet(
                first_channel_number=COUNTRY_CT[0],
                num_channels=COUNTRY_CT[1],
                mtp=COUNTRY_CT[2],
            )
        ]
        if len(country_params) >= min_params_len:
            constraints = []
            for sconstraint in country_params[1:]:
                fcn, noc, mtp = self.__extract_constraints(sconstraint)
                constraints.append(
                    Dot11EltCountryConstraintTriplet(
                        first_channel_number=fcn, num_channels=noc, mtp=mtp
                    )
                )
        return country_code, constraints

    def __convert_csa_to_bytes(self, scsa: str) -> bytes:
        """Converts CSA parameters that are given as a string.

        Args:
            scsa (str): A string delimited by `,`.

        Returns:
            bytes: CSA parameters converted to bytes and appended
                together in the given order.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        csa_params = scsa.split(",")
        if len(csa_params) > len(CSA):
            raise ValueError(
                "Too many parameters provided for Channel Switch Announcement.\n"
                "Expected: [Channel Switch Mode][New Channel Number][Channel Switch Count]"
            )
        csa = [
            int(param, 16) if param.strip().startswith(("0x", "0X")) else int(param)
            for param in csa_params
        ]
        csa.extend(CSA[len(csa) :])

        return bytes(csa)

    def __convert_quiet_to_bytes(self, squiet: str) -> bytes:
        """Converts Quiet parameters that are given as a string.

        Args:
            squiet (str): A string delimited by `,`.

        Returns:
            bytes: Quiet parameters converted to bytes and appended
                together in the given order.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        quiet_params = squiet.split(",")
        if len(quiet_params) > len(QUIET):
            raise ValueError(
                "Too many parameters provided for Quiet.\n"
                "Expected: [Quiet Count][Quiet Period][Quiet Duration][Quiet Offset]"
            )
        quiet = [
            int(param, 16) if param.strip().startswith(("0x", "0X")) else int(param)
            for param in quiet_params
        ]
        quiet.extend(QUIET[len(quiet) :])

        return struct.pack("BBHH", quiet[0], quiet[1], quiet[2], quiet[3])

    def __convert_tpc_to_bytes(self, stpc: str) -> bytes:
        """Converts TPC Report parameters that are given as a string.

        Args:
            stpc (str): A string delimited by `,`.

        Returns:
            bytes: TPC parameters converted to bytes and appended
                together in the given order.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        tpc_params = stpc.split(",")
        if len(tpc_params) > len(TPC_REPORT):
            raise ValueError(
                "Too many parameters provided for Transmit Power Control Report.\n"
                "Expected: [Transmit Power][Link Margin]"
            )
        tpc_report = [
            int(param, 16) if param.strip().startswith(("0x", "0X")) else int(param)
            for param in tpc_params
        ]
        tpc_report.extend(TPC_REPORT[len(tpc_report) :])

        return bytes(tpc_report)

    def __convert_erp_to_header(self, serp: str) -> BeaconLayer:
        """Crafts ERP Information Element based on `config.ini`.

        Args:
            serp (str): A string containing all the ERP parameters.

        Returns:
            BeaconLayer: A layer that defines ERP Information.

        Raises:
            ValueError: If the format given in `config.ini` is wrong.
        """
        serp = serp.strip()
        if not serp.startswith(("0x", "0X")):
            raise ValueError(
                "Invalid Extended Rate PHY Information: ERP is in hex and has to start with the prefix 0x or 0X."
            )

        if not len(serp[2:]) != 1 and not len(serp[2:]) != 2:
            raise ValueError(
                "Invalid Length for Extended Rate PHY Information.\nExpected: 1B"
            )

        erp = int(serp.zfill(2), 16)
        nep = erp >> 7
        up = (erp >> 6) & 0x1
        bp = (erp >> 5) & 0x1
        res = erp & 0x1F

        return Dot11EltERP(
            NonERP_Present=nep, Use_Protection=up, Barker_Preamble_Mode=bp, res=res
        )

    def craft_ext(self) -> Optional[BeaconLayer]:
        """Crafts Beacon Extension based on `config.ini`.

        Returns:
            Optional[BeaconLayer]: An optional layer that defines Beacon Ext.

        Raises:
            ValueError: Raised by the inner methods.
        """
        section = "Beacon Ext"
        packet = Packet()
        if not self.__config.has_section(section):
            return None

        # FHSet: Dwell Time, Hop Set, Hop Pattern, Hop Index
        if self.__config.has_option(section, "FHSet"):
            fhset = self.__convert_fhset_to_bytes(self.__config[section]["FHSet"])
            packet /= Dot11Elt(ID=2, info=fhset)

        # DSSet: Current Channel
        if self.__config.has_option(section, "DSSet"):
            schannel = self.__config[section]["DSSet"]
            channel = (
                int(schannel, 16)
                if schannel.strip().startswith(("0x", "0X"))
                else int(schannel)
            )
            packet /= Dot11EltDSSSet(channel=channel)

        # CFSet: CFP Count, Period, Max Duration in TU, Duration Remaining in TU
        if self.__config.has_option(section, "CFSet"):
            cfset = self.__convert_cfset_to_bytes(self.__config[section]["CFSet"])
            packet /= Dot11Elt(ID=4, info=cfset)

        # IBSS: ATIM Window in TU
        if self.__config.has_option(section, "IBSS"):
            satim = self.__config[section]["IBSS"]
            atim = (
                int(satim, 16) if satim.strip().startswith(("0x", "0X")) else int(satim)
            )
            packet /= Dot11Elt(ID=6, info=struct.pack("H", atim))

        # TIM: DTIM Count, Period, Bitmap Control, Partial Virtual Bitmap
        if self.__config.has_option(section, "TIM"):
            tim = self.__convert_tim_to_bytes(self.__config[section]["TIM"])
            packet /= Dot11Elt(ID=5, info=tim)

        # Country Info: Country String, Country Constraint Triplets
        # Country Constraint Triplet: First Channel Number, Number of Channels, Maximum Transmit Power
        if self.__config.has_option(section, "Country"):
            country, triplets = self.__extract_country_info(
                self.__config[section]["Country"]
            )
            packet /= Dot11EltCountry(country_string=country, descriptors=triplets)

        # Power Constraint: Power Constraint Value in dB
        if self.__config.has_option(section, "PConstraint"):
            spconstraint = self.__config[section]["PConstraint"]
            pconstraint = (
                int(spconstraint, 16)
                if spconstraint.strip().startswith(("0x", "0X"))
                else int(spconstraint)
            )
            packet /= Dot11Elt(ID=32, info=struct.pack("B", pconstraint))

        # Channel Switch Announcement: Channel Switch Mode, New Channel Number, Channel Switch Count
        if self.__config.has_option(section, "CSA"):
            csa = self.__convert_csa_to_bytes(self.__config[section]["CSA"])
            packet /= Dot11Elt(ID=37, info=csa)

        # Quite: Quiet Count, Quiet Period, Quiet Duration, Quiet Offset
        if self.__config.has_option(section, "Quiet"):
            quiet = self.__convert_quiet_to_bytes(self.__config[section]["Quiet"])
            packet /= Dot11Elt(ID=40, info=quiet)

        # Transmit Power Control Report: Transmit Power, Link Margin
        if self.__config.has_option(section, "TPCReport"):
            tpc_report = self.__convert_tpc_to_bytes(
                self.__config[section]["TPCReport"]
            )
            packet /= Dot11Elt(ID=35, info=tpc_report)

        # Extended Rate PHY: Non-ERP Present, Use Protection, Barker Preamble, Reserved
        if self.__config.has_option(section, "ERP"):
            packet /= self.__convert_erp_to_header(self.__config[section]["ERP"])

        # Extended Supported Rates
        if self.__config.has_option(section, "ERates"):
            erates = [
                (
                    int(rate, 16) * 2
                    if rate.strip().startswith(("0x", "0X"))
                    else int(rate) * 2
                )
                for rate in self.__config[section]["ERates"].split(",")
            ]
            packet /= Dot11Elt(ID=50, info=bytes(erates))

        rsn_info = self.__craft_rsn()
        if rsn_info:
            packet /= rsn_info

        return packet

    def craft_from_config(self) -> Beacon:
        """Crafts Beacon frame based on `config.ini`.

        Returns:
            Beacon: A beacon consisting of multiple 802.11 layers.

        Raises:
            SectionNotFoundError: Raised by the inner methods.
            OptionNotFoundError: Raised by the inner methods.
            ValueError: Raised by the inner methods.
        """
        mac_header = self.craft_mac_header()
        beacon_body = self.craft_body()
        beacon_ext = self.craft_ext()

        packet = RadioTap() / mac_header / beacon_body

        if beacon_ext:
            packet /= beacon_ext
        return packet

    def generate_from_config(self, count: Optional[int] = None) -> BeaconGenerator:
        """Generates Beacon frames based on `config.ini`.

        Args:
            count (Optional[int]): Number of frames to be generated. By default,
                `None`. If `None`, generate infinitely.

        Yields:
            Beacon: A beacon consisting of multiple 802.11 layers.

        Raises:
            SectionNotFoundError: Raised by the inner methods.
            OptionNotFoundError: Raised by the inner methods.
            ValueError: Raised by the inner methods.
        """
        sn = SNUMBER
        if self.__config.has_option("MAC Header", "SNumber"):
            ssn = self.__config["MAC Header"]["SNumber"]
            sn = int(ssn, 16) if ssn.strip().startswith(("0x", "0X")) else int(ssn)
            if not (0x000 <= sn <= 0xFFF):
                raise ValueError(
                    "Invalid Sequence Number.\n"
                    "Expected: 0 <= Sequence Number <= 0xFFF"
                )
            self.__config.remove_option("MAC Header", "SNumber")
        mac_header = self.craft_mac_header(sn)
        body_ext = self.craft_body()
        beacon_ext = self.craft_ext()

        if beacon_ext:
            body_ext /= beacon_ext

        i = 0
        while count is None or i < count:
            yield RadioTap() / mac_header / body_ext
            sn = (sn + 1) % 0xFFF
            mac_header = self.craft_mac_header(sn)
            i += 1

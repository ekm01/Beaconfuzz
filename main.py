from injection.config_sender import send_async_from_config
from monitor.monitor import *
from monitor.sniffer import *
import argparse
import math
import os


parser = argparse.ArgumentParser(
    description="beaconfuzz — A Wi-Fi fuzzing tool using only beacon frames.",
    prog="beaconfuzz",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
  *Available filter functions:
    1. subtype_filter(*subtypes: str): filters all frames with the given subtypes
    2. ssid_filter(*ssids: str): filters all frames with the given SSIDs
    3. mac_filter(mac_type: str, mac: str): filters all frames with the MAC
        address 'mac' wrt. 'mac_type' {addr1, addr2, addr3, addr4}
           """,
)

parser.add_argument(
    "-m",
    type=str,
    required=True,
    choices=["send", "monitor", "combined"],
    help="execution mode {send,monitor,combined} (default: send)",
    metavar="<execution mode>",
)
parser.add_argument(
    "-f",
    type=str,
    action="append",
    nargs="+",
    default=None,
    help="filter* for monitor mode, can be provided multiple times (default: None)",
    metavar="<filter>",
)
parser.add_argument(
    "-d",
    type=float,
    default=0.7,
    help="dwell time in seconds (default: 0.7)",
    metavar="<dwell time>",
)
parser.add_argument(
    "-t",
    type=float,
    default=50,
    help="timeout in seconds (default: 50)",
    metavar="<timeout>",
)
parser.add_argument(
    "-i",
    type=str,
    required=True,
    help="Wi-Fi interface",
    metavar="<interface>",
)
parser.add_argument(
    "-c",
    type=int,
    nargs="+",
    default=[6],
    help="channel number, can be provided multiple times (default: 6)",
    metavar="<channel>",
)
parser.add_argument(
    "-b",
    type=int,
    default=None,
    help="channel bandwidth (default: None)",
    metavar="<bandwidth>",
)
parser.add_argument(
    "-p",
    type=str,
    default=None,
    help="path to config file (default: None)",
    metavar="<config ini path>",
)
parser.add_argument(
    "-o",
    type=str,
    default="stdout",
    help="output path for monitoring results, either 'stdout' or 'table' or '<file name>.csv' (default: stdout)",
    metavar="<output path>",
)


def hop(
    timeout: float,
    dwelltime: float,
    channels: List[int],
    curr_channel: List[int],
    iface: str,
) -> None:
    if len(channels) > 1:
        hop_num = math.floor(timeout / dwelltime)
        res = timeout % dwelltime
        i = 0
        for _ in range(hop_num):
            curr_channel[0] = channels[i]
            time.sleep(dwelltime)
            i = (i + 1) % len(channels)
            change_channel(iface=iface, channel=channels[i], verbose=False)
        i += 1
        time.sleep(res)
    else:
        time.sleep(timeout)


def main():
    args = parser.parse_args()

    # Check path
    if args.m in ["send", "combined"]:
        if not args.p:
            print(
                f"Path to the config file '-p' must be provided in case of '{args.m}'.",
                file=sys.stderr,
            )
            exit(1)
        if not os.path.exists(args.p):
            print("Path to the config file is invalid.", file=sys.stderr)
            exit(1)


    # Check timeout
    if args.t < 0:
        print("Timeout cannot be negative.", file=sys.stderr)
        exit(1)

    # Check dwell time
    if args.d < 0:
        print("Dwell time cannot be negative.", file=sys.stderr)
        exit(1)

    if args.d > args.t:
        print("Dwell time cannot be greater than timeout.", file=sys.stderr)
        exit(1)

    # Check channel number
    # Get all available channels
    supported_channels = get_channels(get_phy(args.i))
    for channel in args.c:
        if channel not in supported_channels:
            print(
                f"Channel number is invalid. Please provide a valid channel number: {sorted(supported_channels)}",
                file=sys.stderr,
            )
            exit(1)

    # Check bandwith
    if args.b is not None and args.b < 0:
        print("Channel bandwidth cannot be negative.", file=sys.stderr)
        exit(1)

    # Check filter
    filter_func = None
    if args.f is not None:
        filters = []
        for sfilter in args.f:
            try:
                filter, arg_num = FILTERS[sfilter[0]]
            except KeyError:
                print(
                    f"Invalid filter. Please select a valid filter: {list(FILTERS.keys())}",
                    file=sys.stderr,
                )
                exit(1)
            filter_args = sfilter[1:]

            if arg_num == -1 and len(filter_args) == 0:
                print(
                    f"Please provide at least one arg for '{sfilter[0]}'",
                    file=sys.stderr,
                )
                exit(1)

            if arg_num != -1 and arg_num != len(filter_args):
                print(
                    f"Unexpected number of args provided for '{sfilter[0]}': "
                    f"Expected {arg_num}, but provided {len(filter_args)}",
                    file=sys.stderr,
                )
                exit(1)
            filters.append(filter(*filter_args))

        filter_func = combined_filter(*filters)

    # Check output
    fextension = ".csv"
    if not (
        (len(args.o) > len(fextension) and args.o.endswith(fextension))
        or args.o in ["stdout", "table"]
    ) and args.m != "send":
        print(
            f"Invalid output parameter: Please provide a valid output: {['stdout', 'table', '<file name>' + fextension]}",
            file=sys.stderr,
        )
        exit(1)

    new_iface, procs = set_monitor(
        iface=args.i,
        mode="airmon-ng",
        naive=False,
        channel=args.c[0],
        bandwidth=args.b,
    )

    time.sleep(2)
    curr_channel = [args.c[0]]

    sniffer, live, file = None, None, None
    try:
        if args.m == "send":
            print("Sending beacons...")
            time.sleep(1)
            send_async_from_config(config_path=args.p, iface=new_iface, show=True)
            hop(
                timeout=args.t,
                dwelltime=args.d,
                channels=args.c,
                curr_channel=curr_channel,
                iface=new_iface,
            )
        elif args.m == "monitor":
            print("Monitoring Wi-Fi traffic...")
            time.sleep(1)
            if args.o == "stdout":
                sniffer = sniff_to_stdout(
                    mode="async",
                    iface=new_iface,
                    timeout=args.t,
                    curr_channel=curr_channel,
                    filter=filter_func,
                )
                hop(
                    timeout=args.t,
                    dwelltime=args.d,
                    channels=args.c,
                    curr_channel=curr_channel,
                    iface=new_iface,
                )
                sniffer.join()
            elif args.o == "table":
                sniffer, live = sniff_to_table(
                    mode="async",
                    iface=new_iface,
                    timeout=args.t,
                    curr_channel=curr_channel,
                    filter=filter_func,
                )
                hop(
                    timeout=args.t,
                    dwelltime=args.d,
                    channels=args.c,
                    curr_channel=curr_channel,
                    iface=new_iface,
                )
                sniffer.join()
                live.stop()
            else:
                sniffer, file = sniff_to_csv(
                    output=args.o,
                    mode="async",
                    iface=new_iface,
                    timeout=args.t,
                    curr_channel=curr_channel,
                    filter=filter_func,
                )
                hop(
                    timeout=args.t,
                    dwelltime=args.d,
                    channels=args.c,
                    curr_channel=curr_channel,
                    iface=new_iface,
                )
                sniffer.join()
                file.close()

        else:
            print("Sending and monitoring simultaneously...")
            time.sleep(1)
            if args.o == "stdout":
                sniffer = sniff_to_stdout(
                    mode="async",
                    iface=new_iface,
                    timeout=args.t,
                    curr_channel=curr_channel,
                    filter=filter_func,
                )
                send_async_from_config(
                    config_path=args.p, iface=new_iface, show=True, verbose=False
                )
                hop(
                    timeout=args.t,
                    dwelltime=args.d,
                    channels=args.c,
                    curr_channel=curr_channel,
                    iface=new_iface,
                )
                sniffer.join()
            elif args.o == "table":
                sniffer, live = sniff_to_table(
                    mode="async",
                    iface=new_iface,
                    timeout=args.t,
                    curr_channel=curr_channel,
                    filter=filter_func,
                )
                send_async_from_config(
                    config_path=args.p, iface=new_iface, show=True, verbose=False
                )
                hop(
                    timeout=args.t,
                    dwelltime=args.d,
                    channels=args.c,
                    curr_channel=curr_channel,
                    iface=new_iface,
                )
                sniffer.join()
                live.stop()
            else:
                sniffer, file = sniff_to_csv(
                    output=args.o,
                    mode="async",
                    iface=new_iface,
                    timeout=args.t,
                    curr_channel=curr_channel,
                    filter=filter_func,
                )
                send_async_from_config(
                    config_path=args.p, iface=new_iface, show=True, verbose=False
                )
                hop(
                    timeout=args.t,
                    dwelltime=args.d,
                    channels=args.c,
                    curr_channel=curr_channel,
                    iface=new_iface,
                )
                sniffer.join()
                file.close()

    except KeyboardInterrupt:
        # Clean up
        if sniffer:
            sniffer.stop()
        if live:
            live.stop()
        elif file:
            file.close()

        print("\nInterrupted by user...\n")
    finally:
        # Unset Monitor Mode
        time.sleep(2)
        unset_monitor(new_iface, "airmon-ng", procs)


if __name__ == "__main__":
    main()

#!env python3

#
# wsjt2fdlog
#
# (c) 2023, Jonathan Burchmore KN6LFB
# kn6lfb@arrl.net
#

import struct
import socket
import hashlib
import datetime
import argparse


def parse_wsjt_qint8(pos, packet):
    (value, ) = struct.unpack(">b", packet[pos:pos + 1])
    return pos + 1, value


def parse_wsjt_qint32(pos, packet):
    (value, ) = struct.unpack(">L", packet[pos:pos + 4])
    return pos + 4, value


def parse_wsjt_qint64(pos, packet):
    (value, ) = struct.unpack(">Q", packet[pos:pos + 8])
    return pos + 8, value


def parse_wsjt_qdatetime(pos, packet):
    datetime = {}
    pos, datetime["date"] = parse_wsjt_qint64(pos, packet)
    pos, datetime["time"] = parse_wsjt_qint32(pos, packet)
    pos, timespec = parse_wsjt_qint8(pos, packet)

    if timespec != 1:
        raise NotImplementedError

    return pos, datetime


def parse_wsjt_utf8(pos, packet):
    pos, length = parse_wsjt_qint32(pos, packet)
    if length == 0 or length == 0xFFFFFFFF:
        return pos, ""

    (value, ) = struct.unpack(f"{length}s", packet[pos:pos + length])
    return pos + length, value.decode("utf-8")

#
# From https://sourceforge.net/p/wsjt/wsjtx/ci/master/tree/Network/NetworkMessage.hpp#l46
#
# * QSO Logged    Out       5                      quint32
# *                         Id (unique key)        utf8
# *                         Date & Time Off        QDateTime
# *                         DX call                utf8
# *                         DX grid                utf8
# *                         Tx frequency (Hz)      quint64
# *                         Mode                   utf8
# *                         Report sent            utf8
# *                         Report received        utf8
# *                         Tx power               utf8
# *                         Comments               utf8
# *                         Name                   utf8
# *                         Date & Time On         QDateTime
# *                         Operator call          utf8
# *                         My call                utf8
# *                         My grid                utf8
# *                         Exchange sent          utf8
# *                         Exchange received      utf8
# *                         ADIF Propagation mode  utf8


def parse_wsjt(packet):
    pos, magic = parse_wsjt_qint32(0, packet)
    if magic != 0xadbccbda:
        return None

    pos, schema = parse_wsjt_qint32(pos, packet)
    if schema != 2:
        return None

    pos, packet_type = parse_wsjt_qint32(pos, packet)
    if packet_type != 5:
        return None

    message = {}
    pos, message["id"] = parse_wsjt_utf8(pos, packet)
    pos, message["dt_off"] = parse_wsjt_qdatetime(pos, packet)
    pos, message["dxcall"] = parse_wsjt_utf8(pos, packet)
    pos, message["dxgrid"] = parse_wsjt_utf8(pos, packet)
    pos, message["txfreq"] = parse_wsjt_qint64(pos, packet)
    pos, message["mode"] = parse_wsjt_utf8(pos, packet)
    pos, message["rpt_sent"] = parse_wsjt_utf8(pos, packet)
    pos, message["rpt_rcvd"] = parse_wsjt_utf8(pos, packet)
    pos, message["txpower"] = parse_wsjt_utf8(pos, packet)
    pos, message["comments"] = parse_wsjt_utf8(pos, packet)
    pos, message["name"] = parse_wsjt_utf8(pos, packet)
    pos, message["dt_on"] = parse_wsjt_qdatetime(pos, packet)
    pos, message["opcall"] = parse_wsjt_utf8(pos, packet)
    pos, message["mycall"] = parse_wsjt_utf8(pos, packet)
    pos, message["mygrid"] = parse_wsjt_utf8(pos, packet)
    pos, message["exh_sent"] = parse_wsjt_utf8(pos, packet)
    pos, message["exh_rcvd"] = parse_wsjt_utf8(pos, packet)
    pos, message["propmode"] = parse_wsjt_utf8(pos, packet)

    return message


def fdlog_dtstamp_from_wsjt_datetime(wsjt_datetime):
    return (datetime.datetime(1977, 6, 8) + datetime.timedelta(days=wsjt_datetime["date"] - 2443303, milliseconds=wsjt_datetime["time"])).astimezone().strftime("%y%m%d.%H%M%S")


def fdlog_band(txfreq):
    mhz = txfreq // 1000000

    if mhz == 1:
        return "160d"
    elif mhz == 3:
        return "80d"
    elif mhz == 7:
        return "40d"
    elif mhz == 14:
        return "20d"
    elif mhz == 21:
        return "15d"
    elif mhz >= 28 and mhz <= 29:
        return "10d"
    elif mhz >= 50 and mhz <= 54:
        return "6d"
    elif mhz >= 144 and mhz <= 148:
        return "2d"
    elif mhz >= 222 and mhz <= 225:
        return "220d"
    elif mhz >= 420 and mhz <= 450:
        return "440d"
    elif mhz >= 902 and mhz <= 928:
        return "900d"
    elif mhz >= 1240 and mhz <= 1300:
        return "1200d"

    return "off"


def fdlog_from_wsjt(args, wsjt_message):
    fdlog_message = []
    fdlog_message.append("q")
    fdlog_message.append(args.host)
    fdlog_message.append("-1")
    fdlog_message.append(
        fdlog_dtstamp_from_wsjt_datetime(wsjt_message["dt_off"]))
    fdlog_message.append(fdlog_band(wsjt_message["txfreq"]))
    fdlog_message.append(wsjt_message["dxcall"].lower())
    fdlog_message.append(wsjt_message["exh_rcvd"].lower())
    fdlog_message.append(wsjt_message["txpower"])
    fdlog_message.append(args.op)
    fdlog_message.append(args.logger)

    return "|".join(fdlog_message)


def fdlog_cauth(args, fdlog_message):
    return hashlib.md5((args.authkey + "2004070511111akb" + args.contest + fdlog_message + "\n").encode("utf-8")).hexdigest()


def listen_and_forward(args):
    print(
        f"Forwarding WSJT-X packets on port {args.wsjt_port} to FDLog at {args.fdlog_host}:{args.fdlog_port}")
    print(f"Host: {args.host} Operator: {args.op} Logger: {args.logger}")

    wsjt_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    wsjt_socket.bind(("", args.wsjt_port))

    fdlog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        packet, source_address = wsjt_socket.recvfrom(8192)
        wsjt_message = parse_wsjt(packet)
        if wsjt_message == None:
            continue

        fdlog_message = fdlog_from_wsjt(args, wsjt_message)
        fdlog_socket.sendto(f"{fdlog_cauth(args, fdlog_message)}\n{fdlog_message}\n".encode(
            "utf-8"), (args.fdlog_host, args.fdlog_port))

        print(
            f"{datetime.datetime.now().isoformat()} {wsjt_message['dxcall']} {wsjt_message['exh_rcvd']}")


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="wsjt2fdlog", description="Forward WSJT-X QSO Logged Packets to FDLog")

    parser.add_argument("--wsjt-port", dest="wsjt_port", type=int,
                        default=2237, help="WSJT-X UDP Port (default 2237)")
    parser.add_argument("--fdlog-host", dest="fdlog_host",
                        default="127.0.0.1", help="FDLog Hostname/IP (default 127.0.0.1)")
    parser.add_argument("--fdlog-port", dest="fdlog_port", type=int,
                        default=7373, help="FDLog UDP Port (default 7373)")
    parser.add_argument("--authkey", dest="authkey",
                        default="tst", help="FDLog authkey (default 'tst')")
    parser.add_argument("--contest", dest="contest",
                        default="FD", help="Contest Identifier (default 'fd')")
    parser.add_argument("--host", dest="host", default="JCB-PBP",
                        help="FDLog QSO Host (default 'JCB-PBP')")
    parser.add_argument("--op", dest="op", default="jcb",
                        help="FDLog QSO Operator (default 'jcb')")
    parser.add_argument("--logger", dest="logger", default="jcb",
                        help="FDLog QSO Logger (default 'jcb')")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    listen_and_forward(args)

#!/usr/bin/env python3
"""
sim_auth.py -- RUN GSM ALGORITHM (3GPP TS 51.011) and AUTHENTICATE / RUN UMTS
AUTHENTICATION (3GPP TS 31.102) over PC/SC.

APDU structure was cross-checked against osmocom/pysim source (pySim/commands.py
run_gsm()/authenticate(), pySim/cards.py read_aids()) rather than reconstructed
from memory, so P1/P2/data layout below matches what pySim-shell itself sends.

Install:  pip install pyscard

Usage:
  python sim_auth.py --list-readers
  python sim_auth.py gsm  --rand 00112233445566778899aabbccddeeff
  python sim_auth.py umts --rand <32 hex> --autn <32 hex>
  python sim_auth.py umts --rand <32 hex> --autn <32 hex> --aid a0000000871002...
  python sim_auth.py umts --rand <32 hex> --autn <32 hex> --reader 1 -q
"""

import argparse
import sys

# ---------------------------------------------------------------------------
# Pure protocol helpers -- no pyscard dependency, importable/testable without
# a reader attached.
# ---------------------------------------------------------------------------

def h2b(s: str) -> bytes:
    return bytes.fromhex(s.strip().replace(" ", ""))


def apdu_run_gsm(rand: bytes) -> bytes:
    """RUN GSM ALGORITHM, TS 51.011 sec 9.2. Must be sent under DF_GSM (7F20).
    CLA=A0 INS=88 P1=00 P2=00 Lc=10 <RAND:16> Le=00
    """
    if len(rand) != 16:
        raise ValueError(f"RAND must be 16 bytes, got {len(rand)}")
    return bytes([0xA0, 0x88, 0x00, 0x00, 0x10]) + rand + bytes([0x00])


def parse_run_gsm_resp(data: bytes) -> dict:
    """Classic SIM response is a raw concatenation, no TLV: SRES(4) || Kc(8)."""
    if len(data) < 12:
        raise ValueError(f"Expected 12 bytes (SRES+Kc), got {len(data)}: {data.hex()}")
    return {"sres": data[0:4], "kc": data[4:12]}


def apdu_authenticate(rand: bytes, autn: bytes, context: str = "3g") -> bytes:
    """AUTHENTICATE, TS 31.102 sec 7.1.2.1. Must be sent under ADF.USIM.
    CLA=00 INS=88 P1=00 P2=81(3g)/80(gsm) Lc=<len> LV(RAND) LV(AUTN) Le=00
    context='gsm' runs 2G auth through the USIM (useful when the card has no
    classic DF_GSM at all, which is common on modern-only UICCs).
    """
    if len(rand) != 16:
        raise ValueError(f"RAND must be 16 bytes, got {len(rand)}")
    if len(autn) != 16:
        raise ValueError(f"AUTN must be 16 bytes, got {len(autn)}")
    if context not in ("3g", "gsm"):
        raise ValueError(f"context must be '3g' or 'gsm', got {context!r}")
    p2 = 0x81 if context == "3g" else 0x80
    data = bytes([len(rand)]) + rand + bytes([len(autn)]) + autn
    return bytes([0x00, 0x88, 0x00, p2, len(data)]) + data + bytes([0x00])


def parse_authenticate_resp(data: bytes) -> dict:
    """DB = successful auth: LV(RES) LV(CK) LV(IK) [LV(Kc)]
    DC = sync failure:     LV(AUTS)
    """
    if not data:
        raise ValueError("Empty response")

    def take_lv(buf, i):
        ln = buf[i]
        return buf[i + 1:i + 1 + ln], i + 1 + ln

    tag, i = data[0], 1
    if tag == 0xDB:
        res, i = take_lv(data, i)
        ck, i = take_lv(data, i)
        ik, i = take_lv(data, i)
        out = {"status": "success", "res": res, "ck": ck, "ik": ik}
        if i < len(data):
            kc, i = take_lv(data, i)
            out["kc"] = kc
        return out
    elif tag == 0xDC:
        auts, i = take_lv(data, i)
        return {"status": "sync_failure", "auts": auts}
    else:
        return {"status": "unknown", "raw": data}


def parse_ef_dir_record(rec: bytes):
    """One EF.DIR record: 61 LL 4F LL2 <AID...>. Returns AID hex or None."""
    if len(rec) < 4 or rec[0] != 0x61 or rec[2] != 0x4F:
        return None
    aid_len = rec[3]
    return rec[4:4 + aid_len].hex()


# ---------------------------------------------------------------------------
# pyscard-dependent I/O layer
# ---------------------------------------------------------------------------

def get_connection(reader_index: int):
    from smartcard.System import readers
    from smartcard.Exceptions import NoCardException, CardConnectionException

    rlist = readers()
    if not rlist:
        sys.exit("No PC/SC readers found.")
    if reader_index >= len(rlist):
        sys.exit(f"Reader index {reader_index} out of range ({len(rlist)} found: {rlist}).")
    print(f"[*] Reader: {rlist[reader_index]}")
    conn = rlist[reader_index].createConnection()
    try:
        conn.connect()
    except (NoCardException, CardConnectionException) as e:
        sys.exit(f"Could not connect to card: {e}")
    return conn


def transmit(conn, apdu: bytes, label: str = "", verbose: bool = True):
    apdu_list = list(apdu)
    data, sw1, sw2 = conn.transmit(apdu_list)
    if verbose and label:
        print(f"  -> {label}: {bytes(apdu_list).hex()}")
        print(f"  <- {bytes(data).hex()} SW={sw1:02X}{sw2:02X}")
    if sw1 == 0x61:  # more data available -> GET RESPONSE
        get_resp = [0x00, 0xC0, 0x00, 0x00, sw2]
        data, sw1, sw2 = conn.transmit(get_resp)
        if verbose:
            print(f"  <- (GET RESPONSE) {bytes(data).hex()} SW={sw1:02X}{sw2:02X}")
    elif sw1 == 0x6C:  # wrong Le -> resend with the Le the card told us
        apdu_list[-1] = sw2
        data, sw1, sw2 = conn.transmit(apdu_list)
        if verbose:
            print(f"  <- (resent Le={sw2:02X}) {bytes(data).hex()} SW={sw1:02X}{sw2:02X}")
    return bytes(data), sw1, sw2


def select(conn, fid_or_aid: bytes, by_aid: bool = False, verbose: bool = True) -> bytes:
    p1 = 0x04 if by_aid else 0x00
    apdu = bytes([0x00, 0xA4, p1, 0x04, len(fid_or_aid)]) + fid_or_aid
    label = f"SELECT {'AID' if by_aid else 'FID'} {fid_or_aid.hex()}"
    data, sw1, sw2 = transmit(conn, apdu, label, verbose)
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"SELECT {fid_or_aid.hex()} failed: SW={sw1:02X}{sw2:02X}")
    return data


def find_usim_aid(conn, verbose: bool = True) -> str:
    """Read EF.DIR (3F00/2F00) and return the first AID with the standard
    USIM prefix a0000000871002 (3GPP TS 101.220)."""
    select(conn, h2b("3f00"), verbose=verbose)
    select(conn, h2b("2f00"), verbose=verbose)
    aids = []
    for rec_no in range(1, 21):
        apdu = bytes([0x00, 0xB2, rec_no, 0x04, 0x00])
        data, sw1, sw2 = transmit(conn, apdu, f"READ RECORD {rec_no}", verbose)
        if (sw1, sw2) == (0x90, 0x00) and data:
            aid = parse_ef_dir_record(data)
            if aid:
                aids.append(aid)
        elif sw1 in (0x6A, 0x69):  # record not found / no more records
            break
    for aid in aids:
        if aid.startswith("a0000000871002"):
            return aid
    if aids:
        print(f"[!] No AID with standard USIM prefix found; candidates seen: {aids}")
    raise RuntimeError("Could not find a USIM AID via EF.DIR -- pass --aid explicitly")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def run_gsm(conn, rand_hex: str, verbose: bool = True) -> dict:
    rand = h2b(rand_hex)
    select(conn, h2b("3f00"), verbose=verbose)
    select(conn, h2b("7f20"), verbose=verbose)
    data, sw1, sw2 = transmit(conn, apdu_run_gsm(rand), "RUN GSM ALGORITHM", verbose)
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"RUN GSM ALGORITHM failed: SW={sw1:02X}{sw2:02X}")
    result = parse_run_gsm_resp(data)
    print(f"\nSRES = {result['sres'].hex()}")
    print(f"Kc   = {result['kc'].hex()}")
    return result


def run_umts(conn, rand_hex: str, autn_hex: str, aid_hex: str = None,
             context: str = "3g", verbose: bool = True) -> dict:
    rand, autn = h2b(rand_hex), h2b(autn_hex)
    select(conn, h2b("3f00"), verbose=verbose)
    if not aid_hex:
        aid_hex = find_usim_aid(conn, verbose=verbose)
        print(f"[*] Discovered USIM AID: {aid_hex}")
    select(conn, h2b(aid_hex), by_aid=True, verbose=verbose)
    apdu = apdu_authenticate(rand, autn, context=context)
    data, sw1, sw2 = transmit(conn, apdu, f"AUTHENTICATE ({context})", verbose)
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"AUTHENTICATE failed: SW={sw1:02X}{sw2:02X}")
    result = parse_authenticate_resp(data)
    if result["status"] == "success":
        print(f"\nRES = {result['res'].hex()}")
        print(f"CK  = {result['ck'].hex()}")
        print(f"IK  = {result['ik'].hex()}")
        if "kc" in result:
            print(f"Kc  = {result['kc'].hex()}")
    elif result["status"] == "sync_failure":
        print(f"\nSynchronisation failure -- AUTS = {result['auts'].hex()}")
        print("(SIM rejected the SQN in AUTN. Expected unless AUTN was freshly")
        print(" derived from this card's real Ki/OPc with an in-range SQN.)")
    else:
        print(f"\nUnrecognised response tag 0x{result['raw'][0]:02X}, raw = {result['raw'].hex()}")
    return result


# ---------------------------------------------------------------------------

def main():
    try:
        import smartcard  # noqa: F401
    except ImportError:
        sys.exit("pyscard is required: pip install pyscard")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--reader", type=int, default=0, help="PC/SC reader index (default 0)")
    common.add_argument("-q", "--quiet", action="store_true", help="Suppress APDU trace")

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--list-readers", action="store_true", help="List connected PC/SC readers and exit")
    sub = p.add_subparsers(dest="mode")

    gp = sub.add_parser("gsm", parents=[common], help="RUN GSM ALGORITHM (classic SIM, DF_GSM)")
    gp.add_argument("--rand", required=True, help="16-byte RAND, hex")

    up = sub.add_parser("umts", parents=[common], help="AUTHENTICATE / RUN UMTS AUTHENTICATION (USIM)")
    up.add_argument("--rand", required=True, help="16-byte RAND, hex")
    up.add_argument("--autn", required=True, help="16-byte AUTN, hex")
    up.add_argument("--aid", help="ADF.USIM AID, hex (skips EF.DIR auto-discovery)")
    up.add_argument("--gsm-context", action="store_true",
                     help="Use GSM context (P2=80) instead of 3G context (P2=81), "
                          "e.g. for cards with no classic DF_GSM")

    args = p.parse_args()

    if args.list_readers:
        from smartcard.System import readers
        for i, r in enumerate(readers()):
            print(f"[{i}] {r}")
        return

    if not args.mode:
        p.print_help()
        sys.exit(1)

    conn = get_connection(args.reader)
    try:
        if args.mode == "gsm":
            run_gsm(conn, args.rand, verbose=not args.quiet)
        else:
            ctx = "gsm" if args.gsm_context else "3g"
            run_umts(conn, args.rand, args.autn, args.aid, context=ctx, verbose=not args.quiet)
    except RuntimeError as e:
        sys.exit(f"[!] {e}")
    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()

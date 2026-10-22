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
  python sim_auth.py umts --rand <32 hex> --gsm-context
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
    """Legacy SIM RUN GSM ALGORITHM, TS 51.011 sec. 9.2 (CLA=A0)."""
    if len(rand) != 16:
        raise ValueError(f"RAND must be 16 bytes, got {len(rand)}")
    return bytes([0xA0, 0x88, 0x00, 0x00, 0x10]) + rand + bytes([0x00])


def apdu_authenticate_gsm(rand: bytes) -> bytes:
    """USIM AUTHENTICATE in GSM context, TS 31.102 sec. 7.1.2.1 (CLA=00).

    GSM context carries LV(RAND) only (no AUTN). P2=80 selects GSM context.
    """
    if len(rand) != 16:
        raise ValueError(f"RAND must be 16 bytes, got {len(rand)}")
    data = bytes([len(rand)]) + rand
    return bytes([0x00, 0x88, 0x00, 0x80, len(data)]) + data + bytes([0x00])


def parse_run_gsm_resp(data: bytes) -> dict:
    """Legacy SIM response is a raw concatenation: SRES(4) || Kc(8)."""
    if len(data) < 12:
        raise ValueError(f"Expected 12 bytes (SRES+Kc), got {len(data)}: {data.hex()}")
    return {"sres": data[0:4], "kc": data[4:12]}


def parse_usim_gsm_resp(data: bytes) -> dict:
    """USIM GSM-context response: LV(SRES) || LV(Kc), without a DB tag."""
    if len(data) < 2:
        raise ValueError(f"Expected LV(SRES)||LV(Kc), got {len(data)} bytes: {data.hex()}")
    sres_len = data[0]
    if sres_len != 4 or len(data) < 1 + sres_len + 1:
        raise ValueError(f"Invalid USIM GSM SRES length/response: {data.hex()}")
    sres = data[1:1 + sres_len]
    kc_len_offset = 1 + sres_len
    kc_len = data[kc_len_offset]
    kc_start = kc_len_offset + 1
    if kc_len != 8 or len(data) != kc_start + kc_len:
        raise ValueError(f"Invalid USIM GSM Kc length/response: {data.hex()}")
    return {"sres": sres, "kc": data[kc_start:kc_start + kc_len]}


def apdu_authenticate(rand: bytes, autn: bytes | None = None,
                      context: str = "3g") -> bytes:
    """Build a USIM AUTHENTICATE APDU (3GPP TS 31.102 §7.1.2.1).

    GSM context (P2=80) carries LV(RAND) only; AUTN is not sent and must be
    omitted. 3G context (P2=81) carries LV(RAND) || LV(AUTN).
    Must be sent after selecting ADF.USIM using CLA=00.
    """
    if len(rand) != 16:
        raise ValueError(f"RAND must be 16 bytes, got {len(rand)}")
    if context not in ("3g", "gsm"):
        raise ValueError(f"context must be '3g' or 'gsm', got {context!r}")

    if context == "gsm":
        if autn is not None:
            raise ValueError("AUTN must be omitted for GSM context; only LV(RAND) is sent")
        return apdu_authenticate_gsm(rand)

    if autn is None:
        raise ValueError("AUTN is required for 3G context")
    if len(autn) != 16:
        raise ValueError(f"AUTN must be 16 bytes, got {len(autn)}")
    data = bytes([len(rand)]) + rand + bytes([len(autn)]) + autn
    return bytes([0x00, 0x88, 0x00, 0x81, len(data)]) + data + bytes([0x00])


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
    if sw1 in (0x61, 0x9F):  # more data available (UICC / legacy SIM)
        get_cla = 0xA0 if sw1 == 0x9F else 0x00
        get_resp = [get_cla, 0xC0, 0x00, 0x00, sw2]
        data, sw1, sw2 = conn.transmit(get_resp)
        if verbose:
            print(f"  <- (GET RESPONSE) {bytes(data).hex()} SW={sw1:02X}{sw2:02X}")
    elif sw1 == 0x6C:  # wrong Le -> resend with the Le the card told us
        apdu_list[-1] = sw2
        data, sw1, sw2 = conn.transmit(apdu_list)
        if verbose:
            print(f"  <- (resent Le={sw2:02X}) {bytes(data).hex()} SW={sw1:02X}{sw2:02X}")
    return bytes(data), sw1, sw2


def select(conn, fid_or_aid: bytes, by_aid: bool = False,
           verbose: bool = True, cla: int = 0x00) -> bytes:
    if by_aid and cla != 0x00:
        raise ValueError("ADF selection by AID must use CLA=00")
    p1 = 0x04 if by_aid else 0x00
    # Legacy SIM SELECT uses A0 and P2=00; UICC/USIM SELECT uses CLA=00,
    # requesting the FCI template with P2=04 as before.
    p2 = 0x04 if (by_aid or cla == 0x00) else 0x00
    apdu = bytes([cla, 0xA4, p1, p2, len(fid_or_aid)]) + fid_or_aid
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
    """Run GSM authentication via USIM (CLA=00) when available, else classic SIM (CLA=A0)."""
    rand = h2b(rand_hex)
    if len(rand) != 16:
        raise ValueError(f"RAND must be 16 bytes, got {len(rand)}")

    # Prefer the USIM application when EF.DIR advertises a selectable USIM AID.
    usim_aid = None
    try:
        usim_aid = find_usim_aid(conn, verbose=verbose)
        select(conn, h2b(usim_aid), by_aid=True, verbose=verbose)
    except RuntimeError as exc:
        print(f"[*] No selectable ADF.USIM detected ({exc}); trying classic SIM path")
        usim_aid = None

    if usim_aid:
        print(f"[*] Using USIM GSM context (CLA=00, AID={usim_aid})")
        apdu = apdu_authenticate_gsm(rand)
        data, sw1, sw2 = transmit(conn, apdu, "AUTHENTICATE (GSM context, USIM)", verbose)
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError(f"USIM AUTHENTICATE (GSM context) failed: SW={sw1:02X}{sw2:02X}")
        result = parse_usim_gsm_resp(data)
    else:
        # Some cards accept UICC CLA=00 for SELECT even without a USIM applet;
        # try that path first, then retry SELECT using legacy SIM CLA=A0.
        try:
            select(conn, h2b("3f00"), verbose=verbose)
            select(conn, h2b("7f20"), verbose=verbose)
        except RuntimeError:
            select(conn, h2b("3f00"), verbose=verbose, cla=0xA0)
            select(conn, h2b("7f20"), verbose=verbose, cla=0xA0)
        print("[*] Using classic SIM RUN GSM ALGORITHM (CLA=A0)")
        data, sw1, sw2 = transmit(conn, apdu_run_gsm(rand), "RUN GSM ALGORITHM", verbose)
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError(f"RUN GSM ALGORITHM failed: SW={sw1:02X}{sw2:02X}")
        result = parse_run_gsm_resp(data)

    print(f"\nSRES = {result['sres'].hex()}")
    print(f"Kc   = {result['kc'].hex()}")
    return result


def run_umts(conn, rand_hex: str, autn_hex: str | None = None,
             aid_hex: str = None, context: str = "3g",
             verbose: bool = True) -> dict:
    """Run USIM AUTHENTICATE in 3G or GSM context.

    In 3G context, AUTN is required and the response is parsed as RES/CK/IK
    (or AUTS on synchronisation failure). In GSM context, AUTN must be omitted;
    the APDU carries only RAND and the response contains SRES and Kc.
    """
    if context not in ("3g", "gsm"):
        raise ValueError(f"context must be '3g' or 'gsm', got {context!r}")

    rand = h2b(rand_hex)
    if len(rand) != 16:
        raise ValueError(f"RAND must be 16 bytes, got {len(rand)}")

    if context == "gsm":
        if autn_hex is not None:
            raise ValueError("--autn must be omitted with --gsm-context")
        autn = None
    else:
        if autn_hex is None:
            raise ValueError("--autn is required unless --gsm-context is used")
        autn = h2b(autn_hex)
        if len(autn) != 16:
            raise ValueError(f"AUTN must be 16 bytes, got {len(autn)}")

    select(conn, h2b("3f00"), verbose=verbose)
    if not aid_hex:
        aid_hex = find_usim_aid(conn, verbose=verbose)
        print(f"[*] Discovered USIM AID: {aid_hex}")
    select(conn, h2b(aid_hex), by_aid=True, verbose=verbose)

    apdu = apdu_authenticate(rand, autn, context=context)
    data, sw1, sw2 = transmit(conn, apdu, f"AUTHENTICATE ({context})", verbose)
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"AUTHENTICATE ({context}) failed: SW={sw1:02X}{sw2:02X}")

    if context == "gsm":
        result = parse_usim_gsm_resp(data)
        print(f"\nSRES = {result['sres'].hex()}")
        print(f"Kc   = {result['kc'].hex()}")
        return result

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

    gp = sub.add_parser("gsm", parents=[common], help="GSM authentication (auto-select USIM or classic SIM)")
    gp.add_argument("--rand", required=True, help="16-byte RAND, hex")

    up = sub.add_parser("umts", parents=[common], help="AUTHENTICATE / RUN UMTS AUTHENTICATION (USIM)")
    up.add_argument("--rand", required=True, help="16-byte RAND, hex")
    up.add_argument("--autn", help="16-byte AUTN, hex (required for 3G context; omit with --gsm-context)")
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

    if args.mode == "umts":
        if args.gsm_context and args.autn is not None:
            up.error("--autn must be omitted with --gsm-context; GSM context uses RAND only")
        if not args.gsm_context and args.autn is None:
            up.error("--autn is required unless --gsm-context is specified")

    conn = get_connection(args.reader)
    try:
        if args.mode == "gsm":
            run_gsm(conn, args.rand, verbose=not args.quiet)
        else:
            ctx = "gsm" if args.gsm_context else "3g"
            run_umts(conn, args.rand, args.autn, args.aid, context=ctx, verbose=not args.quiet)
    except (RuntimeError, ValueError) as e:
        sys.exit(f"[!] {e}")
    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()

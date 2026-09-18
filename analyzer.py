#!/usr/bin/env python3
"""
Phone Security Analyzer
========================

A small, beginner-friendly CLI tool that validates and analyzes a phone
number using only legitimate, public information sources:

  * The `phonenumbers` library (Google's libphonenumber port) for
    parsing, validation, region/country detection, and number-type
    guessing (mobile / landline / VoIP / etc).
  * An optional, legitimate carrier-lookup API (Numverify / apilayer)
    for carrier and line-type data, if you provide an API key.
  * An optional, legitimate Twilio Lookup v2 "SIM Swap" signal, ONLY
    if your Twilio account is explicitly entitled to that package.
    This is a legally-gated, opt-in fraud-prevention feature offered
    by Twilio to approved accounts -- this tool does not, and cannot,
    bypass that entitlement check.

WHAT THIS TOOL WILL NEVER DO
-----------------------------
  * It will never try to obtain GPS / live location.
  * It will never try to obtain call history, CDRs, SMS history,
    contacts, subscriber identity, or any private telecom record.
  * It will never attempt to bypass carrier authentication, law
    enforcement systems, or any access control.
  * It will never scrape private/unauthorized databases.
  * It will never store your phone number to disk by default.
  * It will never invent data. If an API/library does not return a
    field, the report clearly says so instead of guessing.

Credentials are read from environment variables only (see .env.example).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

try:
    import phonenumbers
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import timezone as pn_timezone
except ImportError:
    print("Missing dependency 'phonenumbers'. Install with: pip install -r requirements.txt")
    sys.exit(1)

# python-dotenv is optional convenience — the tool still works with
# plain environment variables if it's not installed.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

NOT_AVAILABLE = "Not publicly available / requires authorized access"
NOT_CONFIGURED = "Not checked (no API key configured)"

NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "").strip()
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()

REQUEST_TIMEOUT_SECONDS = 8

NUMBER_TYPE_LABELS = {
    phonenumbers.PhoneNumberType.MOBILE: "Mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE: "Landline (fixed line)",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Landline or Mobile (ambiguous)",
    phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "Shared cost",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal number",
    phonenumbers.PhoneNumberType.PAGER: "Pager",
    phonenumbers.PhoneNumberType.UAN: "Universal Access Number (UAN)",
    phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
}


@dataclass
class Report:
    """Holds every field of the security report. Fields default to the
    'not available' sentinel so we never accidentally imply we know
    something we don't."""

    raw_input: str = ""
    e164: Optional[str] = None
    is_valid: bool = False
    is_possible: bool = False
    country_name: str = NOT_AVAILABLE
    region_code: Optional[str] = None
    number_type: str = "Unknown"
    timezones: list = field(default_factory=list)

    carrier_source: str = NOT_CONFIGURED
    carrier_name: str = NOT_AVAILABLE
    line_type_api: str = NOT_AVAILABLE

    sim_swap_checked: bool = False
    sim_swap_result: str = NOT_AVAILABLE

    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def normalize_and_parse(country_code: str, number: str) -> "phonenumbers.PhoneNumber":
    """Combine a country code and local number into a parseable string
    and hand it to phonenumbers. Accepts input with or without '+'."""

    country_code = country_code.strip().lstrip("+")
    number = number.strip()

    if number.startswith("+"):
        # Number already looks like it includes a country code.
        candidate = number
    else:
        candidate = f"+{country_code}{number}"

    return phonenumbers.parse(candidate, None)


def analyze_locally(parsed: "phonenumbers.PhoneNumber", report: Report) -> None:
    """Fill in everything we can determine offline via phonenumbers.
    This never touches the network and never claims data it doesn't have."""

    report.is_valid = phonenumbers.is_valid_number(parsed)
    report.is_possible = phonenumbers.is_possible_number(parsed)

    if report.is_valid or report.is_possible:
        report.e164 = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        )

    region_code = phonenumbers.region_code_for_number(parsed)
    report.region_code = region_code

    country_name = pn_geocoder.description_for_number(parsed, "en")
    report.country_name = country_name if country_name else (region_code or NOT_AVAILABLE)

    if report.is_valid:
        num_type = phonenumbers.number_type(parsed)
        report.number_type = NUMBER_TYPE_LABELS.get(num_type, "Unknown")
    else:
        report.number_type = "Unknown (number did not validate)"

    zones = pn_timezone.time_zones_for_number(parsed)
    report.timezones = list(zones) if zones else []

    # phonenumbers ships a small, offline, publicly-sourced carrier
    # mapping table. It's often empty for mobile-ported numbers — that's
    # expected and not an error.
    offline_carrier = pn_carrier.name_for_number(parsed, "en")
    if offline_carrier:
        report.carrier_name = offline_carrier
        report.carrier_source = "phonenumbers (offline public mapping)"


def query_numverify(e164_number: str, report: Report) -> None:
    """Query the Numverify (apilayer) validation API for publicly
    available carrier / line-type data. Only runs if an API key is
    configured. Handles errors, rate limits, and missing fields
    gracefully."""

    if not NUMVERIFY_API_KEY:
        return

    url = "http://apilayer.net/api/validate"
    params = {
        "access_key": NUMVERIFY_API_KEY,
        "number": e164_number,
        "format": 1,
    }

    try:
        resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.exceptions.Timeout:
        report.warnings.append("Numverify lookup timed out; carrier data unavailable.")
        return
    except requests.exceptions.RequestException as exc:
        report.warnings.append(f"Numverify lookup failed (network error): {exc}")
        return

    if resp.status_code == 429:
        report.warnings.append("Numverify rate limit reached; try again later.")
        return
    if resp.status_code != 200:
        report.warnings.append(f"Numverify returned HTTP {resp.status_code}; skipping carrier data.")
        return

    try:
        data = resp.json()
    except ValueError:
        report.warnings.append("Numverify returned an unreadable response.")
        return

    if isinstance(data, dict) and data.get("error"):
        err_info = data["error"].get("info", "Unknown API error")
        report.warnings.append(f"Numverify API error: {err_info}")
        return

    if not data.get("valid", False):
        report.warnings.append("Numverify reports this number as invalid/unverifiable.")

    report.carrier_source = "Numverify API"
    report.carrier_name = data.get("carrier") or NOT_AVAILABLE
    report.line_type_api = data.get("line_type") or NOT_AVAILABLE


def query_twilio_sim_swap(e164_number: str, report: Report) -> None:
    """Query Twilio Lookup v2 for the SIM Swap risk signal. This is a
    legally-restricted, opt-in fraud-prevention package: Twilio only
    returns this data to accounts that have been explicitly approved
    for it. This function never attempts to bypass that -- if the
    account isn't entitled, Twilio itself will refuse and we report
    that plainly."""

    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN):
        return

    report.sim_swap_checked = True
    url = f"https://lookups.twilio.com/v2/PhoneNumbers/{e164_number}"
    params = {"Fields": "sim_swap"}

    try:
        resp = requests.get(
            url,
            params=params,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.exceptions.Timeout:
        report.warnings.append("Twilio SIM-swap lookup timed out.")
        return
    except requests.exceptions.RequestException as exc:
        report.warnings.append(f"Twilio SIM-swap lookup failed (network error): {exc}")
        return

    if resp.status_code == 429:
        report.warnings.append("Twilio rate limit reached; SIM-swap check skipped.")
        return
    if resp.status_code == 403:
        report.warnings.append(
            "Twilio account is not authorized/entitled for the SIM Swap package; "
            "this data legitimately requires Twilio approval."
        )
        return
    if resp.status_code != 200:
        report.warnings.append(f"Twilio returned HTTP {resp.status_code}; SIM-swap check skipped.")
        return

    try:
        data = resp.json()
    except ValueError:
        report.warnings.append("Twilio returned an unreadable response.")
        return

    sim_swap = data.get("sim_swap")
    if not sim_swap:
        report.sim_swap_result = NOT_AVAILABLE
        return

    risk = sim_swap.get("swapped_period") or sim_swap.get("last_sim_swap")
    if risk:
        report.sim_swap_result = str(risk)
    else:
        report.sim_swap_result = "Returned by Twilio, but no risk fields were present."


def build_report(country_code: str, number: str, do_lookup: bool, do_sim_swap: bool) -> Report:
    report = Report(raw_input=f"{country_code} {number}".strip())

    try:
        parsed = normalize_and_parse(country_code, number)
    except phonenumbers.NumberParseException as exc:
        report.errors.append(f"Could not parse number: {exc}")
        return report

    analyze_locally(parsed, report)

    if not report.is_possible:
        report.errors.append(
            "This does not look like a possible phone number for the given country code."
        )
        return report

    if report.e164 and do_lookup:
        query_numverify(report.e164, report)

    if report.e164 and do_sim_swap:
        query_twilio_sim_swap(report.e164, report)

    return report


def format_report_text(report: Report) -> str:
    lines = []
    line = lines.append

    line("=" * 56)
    line("        PHONE SECURITY ANALYZER — REPORT")
    line("=" * 56)

    if report.errors:
        line(f"Input: {report.raw_input}")
        line("")
        line("ERRORS:")
        for e in report.errors:
            line(f"  ✗ {e}")
        line("=" * 56)
        return "\n".join(lines)

    validity = "VALID" if report.is_valid else ("POSSIBLE, but not confirmed valid" if report.is_possible else "INVALID")
    line(f"Input number        : {report.raw_input}")
    line(f"Normalized (E.164)  : {report.e164 or NOT_AVAILABLE}")
    line(f"Validation status   : {validity}")
    line("-" * 56)
    line(f"Detected country    : {report.country_name}")
    line(f"Region code         : {report.region_code or NOT_AVAILABLE}")
    line(f"Possible number type: {report.number_type}")
    line(f"Timezone(s)         : {', '.join(report.timezones) if report.timezones else NOT_AVAILABLE}")
    line("-" * 56)
    line("CARRIER / NETWORK INFORMATION")
    line(f"  Source            : {report.carrier_source}")
    line(f"  Carrier name      : {report.carrier_name}")
    line(f"  Line type (API)   : {report.line_type_api}")
    line("-" * 56)
    line("SECURITY SIGNALS (optional, authorized access only)")
    if report.sim_swap_checked:
        line(f"  SIM-swap signal   : {report.sim_swap_result}")
    else:
        line(f"  SIM-swap signal   : {NOT_CONFIGURED}")
    line("-" * 56)
    line("PRIVACY NOTE")
    line("  Location (GPS), call history, SMS history, contacts, and")
    line("  subscriber identity are never requested by this tool.")
    line(f"  Such data is: {NOT_AVAILABLE}")

    if report.warnings:
        line("-" * 56)
        line("WARNINGS:")
        for w in report.warnings:
            line(f"  ⚠ {w}")

    line("=" * 56)
    return "\n".join(lines)


def report_to_dict(report: Report) -> dict:
    return {
        "input": report.raw_input,
        "e164": report.e164,
        "is_valid": report.is_valid,
        "is_possible": report.is_possible,
        "country_name": report.country_name,
        "region_code": report.region_code,
        "number_type": report.number_type,
        "timezones": report.timezones,
        "carrier": {
            "source": report.carrier_source,
            "name": report.carrier_name,
            "line_type_api": report.line_type_api,
        },
        "security_signals": {
            "sim_swap_checked": report.sim_swap_checked,
            "sim_swap_result": report.sim_swap_result,
        },
        "warnings": report.warnings,
        "errors": report.errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Phone Security Analyzer — validate a phone number and show "
        "only publicly/legitimately available information.",
    )
    parser.add_argument(
        "-c", "--country-code",
        required=True,
        help="International country code, e.g. 1, +91, 44",
    )
    parser.add_argument(
        "-n", "--number",
        required=True,
        help="Phone number, local or already-international format",
    )
    parser.add_argument(
        "--no-lookup",
        action="store_true",
        help="Skip the carrier-lookup API call and use offline data only",
    )
    parser.add_argument(
        "--sim-swap",
        action="store_true",
        help="Attempt the optional Twilio SIM-swap signal (requires an "
        "authorized Twilio account with that package enabled)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the report as JSON instead of a formatted terminal report",
    )

    args = parser.parse_args()

    report = build_report(
        country_code=args.country_code,
        number=args.number,
        do_lookup=not args.no_lookup,
        do_sim_swap=args.sim_swap,
    )

    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
    else:
        print(format_report_text(report))

    # Nothing is written to disk here — the report exists only for
    # this run, in memory, satisfying the "no permanent storage" rule.
    sys.exit(0 if not report.errors else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(130)

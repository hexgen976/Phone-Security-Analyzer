# Phone Security Analyzer

A small, beginner-friendly Python 3 CLI tool that validates a phone number
and reports **only** publicly/legitimately available information:

- E.164 normalization and validation (via the `phonenumbers` library —
  a Python port of Google's `libphonenumber`)
- Country / region detection
- Likely number type (mobile, landline, VoIP, toll-free, etc.) when it
  can be determined
- Carrier/network name via an optional, legitimate lookup API
  ([Numverify](https://numverify.com))
- An optional, **account-gated** SIM-swap risk signal via
  [Twilio Lookup v2](https://www.twilio.com/docs/lookup/v2-api/sim-swap)
  — only works if your own Twilio account has been approved by Twilio
  for that package
- A clean terminal (or JSON) security report

## What this tool intentionally does NOT do

- ❌ No GPS / live location tracking
- ❌ No call history, CDRs, SMS history, contacts, or subscriber identity
- ❌ No bypassing of carrier authentication, law-enforcement systems,
  accounts, or access controls
- ❌ No scraping of private/unauthorized databases
- ❌ No permanent storage of phone numbers (nothing is written to disk
  by the tool itself)
- ❌ No hard-coded API keys — credentials are read only from
  environment variables (`.env`)

Any data point that an API or library doesn't actually return is shown
as **"Not publicly available / requires authorized access"** — the
tool never guesses or fabricates information.

---

## Project structure

```
phone-security-analyzer/
├── analyzer.py        # main CLI tool
├── requirements.txt    # minimal dependencies
├── .env.example         # template for API credentials
├── .gitignore
└── README.md
```

---

## 1. Installation — Termux (Android)

```bash
# Update packages
pkg update && pkg upgrade -y

# Install Python and git
pkg install python git -y

# Clone / copy the project, then enter it
cd phone-security-analyzer

# (Recommended) create a virtual environment
pip install --upgrade pip
pip install -r requirements.txt

# Set up your environment file
cp .env.example .env
# Edit .env with nano/vim to add your optional API keys
nano .env
```

> Termux note: if `pip install requests` ever fails to build, run
> `pkg install python-pip clang` first, then retry.

## 2. Installation — Kali Linux

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip -y

cd phone-security-analyzer

# Use a virtual environment to keep things isolated from system Python
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

cp .env.example .env
nano .env
```

## 3. Installation — Debian / Ubuntu Linux

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip -y

cd phone-security-analyzer

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

cp .env.example .env
nano .env
```

---

## Configuration

Copy `.env.example` to `.env` and fill in only the keys you actually
have. All fields are optional — the tool works with **zero** API keys
using offline validation only (`--no-lookup`), it just won't have
carrier data.

```
NUMVERIFY_API_KEY=your_key_here      # optional, for carrier/line-type data
TWILIO_ACCOUNT_SID=your_sid_here     # optional, for --sim-swap only
TWILIO_AUTH_TOKEN=your_token_here    # optional, for --sim-swap only
```

- Get a free Numverify key at https://numverify.com
- SIM-swap data requires a Twilio account that Twilio has separately
  approved for the SIM Swap package — see
  https://www.twilio.com/docs/lookup/v2-api/sim-swap. This tool
  cannot unlock that feature for you; it only calls the API and
  reports whatever Twilio legitimately returns.

---

## Usage

```bash
python3 analyzer.py -c <country_code> -n <phone_number> [options]
```

| Flag | Description |
|---|---|
| `-c`, `--country-code` | International country code, e.g. `1`, `+91`, `44` |
| `-n`, `--number` | Phone number (local or international format) |
| `--no-lookup` | Skip the carrier API call, offline validation only |
| `--sim-swap` | Attempt the optional Twilio SIM-swap signal |
| `--json` | Output the report as JSON |

### Examples

```bash
# Basic check, offline only
python3 analyzer.py -c 1 -n 2015550123 --no-lookup

# Full check with carrier lookup (requires NUMVERIFY_API_KEY in .env)
python3 analyzer.py -c 91 -n 9876543210

# Full check plus SIM-swap signal (requires an approved Twilio account)
python3 analyzer.py -c 44 -n 7911123456 --sim-swap

# Machine-readable output
python3 analyzer.py -c 1 -n 2015550123 --json
```

---

## Sample terminal output

```
$ python3 analyzer.py -c 1 -n 2015550123 --no-lookup

========================================================
        PHONE SECURITY ANALYZER — REPORT
========================================================
Input number        : 1 2015550123
Normalized (E.164)  : +12015550123
Validation status   : VALID
--------------------------------------------------------
Detected country    : United States
Region code         : US
Possible number type: Landline or Mobile (ambiguous)
Timezone(s)         : America/New_York
--------------------------------------------------------
CARRIER / NETWORK INFORMATION
  Source            : Not checked (no API key configured)
  Carrier name      : Not publicly available / requires authorized access
  Line type (API)   : Not publicly available / requires authorized access
--------------------------------------------------------
SECURITY SIGNALS (optional, authorized access only)
  SIM-swap signal   : Not checked (no API key configured)
--------------------------------------------------------
PRIVACY NOTE
  Location (GPS), call history, SMS history, contacts, and
  subscriber identity are never requested by this tool.
  Such data is: Not publicly available / requires authorized access
========================================================
```

With a Numverify key configured (no `--no-lookup`), the "CARRIER /
NETWORK INFORMATION" section fills in with real data such as:

```
CARRIER / NETWORK INFORMATION
  Source            : Numverify API
  Carrier name      : Verizon Wireless
  Line type (API)   : mobile
```

---

## How errors and edge cases are handled

- **Invalid number** → reported clearly under `ERRORS`, exit code `1`
- **API timeout / network error** → logged as a `WARNING`, rest of
  the offline report is still shown
- **API rate limit (HTTP 429)** → logged as a `WARNING`, no crash
- **Missing/empty API fields** → shown as "Not publicly available /
  requires authorized access" rather than guessed
- **No API key configured** → that section is skipped and labeled
  "Not checked (no API key configured)"
- **Twilio SIM-swap not entitled (HTTP 403)** → clearly reported as
  an authorization limitation, not an error in the tool

---

## Extending this project (learning ideas)

- Add a second carrier-lookup backend (e.g. Twilio Lookup v2 basic
  fields) and let the user pick with a `--provider` flag
- Add a `--rate-limit-delay` flag for bulk/batch-style safe usage
- Add unit tests around `normalize_and_parse` and `build_report`
  using `unittest`/`pytest` with mocked API responses
- Add colorized output with the `rich` library (still keeps
  dependencies minimal)

## License / Ethics

This tool is intended for **authorized, educational, and legitimate
security research use only** — for example, verifying your own
numbers, validating user-submitted numbers in a signup form, or
learning how phone-number validation and legitimate lookup APIs work.
Do not use it against numbers you do not have authorization to
investigate.

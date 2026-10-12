"""Extra hard cases for extractor/extract.py.  Run:  python -m extractor.tests_extra"""
from extractor.extract import extract_entities, classify_scam

CASES = [
    # (text, expected set of (type, value))
    ("pay to taskbonus@okaxis.", {("upi_id", "taskbonus@okaxis")}),
    ("Send to rahul.kyc@oksbi, then call", {("upi_id", "rahul.kyc@oksbi")}),
    ("UPI: help@ibl ok", {("upi_id", "help@ibl")}),
    ("pay 919876543210@upi", {("upi_id", "919876543210@upi")}),
    ("pay to quick​loan@paytm", {("upi_id", "quickloan@paytm")}),
    ("Send money to test@upi or test2@ybl", {("upi_id", "test@upi"), ("upi_id", "test2@ybl")}),
    ("mail kbc.desk@gmail.com.", {("email", "kbc.desk@gmail.com")}),
    ("Email me at support@paytm.com", {("email", "support@paytm.com")}),
    ("Call 98765-43210 now!", {("phone", "+919876543210")}),
    ("number is +91 98765 43210.", {("phone", "+919876543210")}),
    ("call 098765 43210", {("phone", "+919876543210")}),
    ("whatsapp9876543210", {("phone", "+919876543210")}),
    ("உங்கள் கணக்கு 9876501234 அழைக்கவும்", {("phone", "+919876501234")}),
    ("visit https://sbi-kyc-update.in/verify?x=1.", {("url", "sbi-kyc-update.in/verify")}),
    ("open www.QuickLoan-Pro.app", {("url", "quickloan-pro.app")}),
    ("Contact t.me/refundhelp", {("url", "t.me/refundhelp")}),
    ("Go to bit.ly/test to get refund", {("url", "bit.ly/test")}),
    ("A/c no 123456789012 IFSC SBIN0001234", {("bank_account", "123456789012"), ("ifsc", "SBIN0001234")}),
    ("ifsc hdfc0001234 pls", {("ifsc", "HDFC0001234")}),
    ("send USDT to 0xa1D4A3FaeA43a3B2ba04449bFCbBdfB0065A4012 now", {("crypto_wallet", "0xa1d4a3faea43a3b2ba04449bfcbbdfb0065a4012")}),
    ("send to 0x6a08134309466F306d2bA216B74BFBEfE531f40D", {("crypto_wallet", "0x6a08134309466f306d2ba216b74bfbefe531f40d")}),
    ("wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", {("crypto_wallet", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")}),
    ("case no 4471 at 9.30pm, fee 12500", set()),
    ("amount ₹4,999 only", set()),
    ("hello madam how are you", set()),
]
TYPES = [
    ("Your SBI account will be blocked today, update PAN now", "kyc_update"),
    ("You have won 25 lakh in KBC", "lottery_prize"),
    ("Earn 3000 per day liking videos, part time job", "job_task"),
    ("This is Mumbai police, FIR registered against you", "digital_arrest"),
    ("Get instant loan without CIBIL", "loan_app"),
    ("Invest 10k get double in 2 days", "investment"),
    ("Your Amazon refund is pending, accept collect request", "refund_collect"),
    ("our company is offering you a job", "job_task"),   # "pan" inside "company" must not trigger KYC
    ("hello how are you", "unknown"),
]

if __name__ == "__main__":
    fails = 0
    for text, exp in CASES:
        got = {(e.type, e.value) for e in extract_entities(text, "m_test")}
        ok = got == exp
        fails += not ok
        print(("PASS" if ok else "FAIL") + f": {text!r}" + ("" if ok else f"\n      expected {sorted(exp)}\n      got      {sorted(got)}"))
    for text, exp in TYPES:
        got = classify_scam(text)
        ok = got == exp
        fails += not ok
        print(("PASS" if ok else "FAIL") + f": type {got!r} <- {text!r}" + ("" if ok else f" (expected {exp!r})"))
    print(f"\n{len(CASES) + len(TYPES) - fails}/{len(CASES) + len(TYPES)} passed")
    raise SystemExit(1 if fails else 0)

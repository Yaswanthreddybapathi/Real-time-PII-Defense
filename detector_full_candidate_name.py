import csv
import json
import re
import sys

# --- REGEXES FOR PII STANDALONE --- #
PHONE_REGEX = re.compile(r'\b\d{10}\b')
AADHAR_REGEX = re.compile(r'\b\d{12}\b')
PASSPORT_REGEX = re.compile(r'\b[A-PR-WYa-pr-wy][0-9]{7}\b')
UPI_REGEX = re.compile(r'\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b')

# --- UTILITY MASKING FUNCTIONS --- #
def mask_phone(value):
    return value[:2] + "XXXXXX" + value[-2:] if len(value) == 10 else "[REDACTED_PII]"

def mask_aadhar(value):
    return value[:4] + "XXXX" + value[-4:] if len(value) == 12 else "[REDACTED_PII]"

def mask_passport(value):
    if len(value) == 8 and value[1:].isdigit():
        return value[0] + "XXXXXXX"
    else:
        return "[REDACTED_PII]"

def mask_name(name):
    # Mask all but first letter of each part
    if not name or not isinstance(name, str): return name
    parts = name.split()
    return " ".join([p[0] + "X"*(len(p)-1) if len(p) > 1 else p for p in parts])

def mask_email(email):
    try:
        user, domain = email.split('@')
        return user[0] + "X"*(len(user)-1) + '@' + domain
    except Exception:
        return "[REDACTED_PII]"

def mask_address(addr):
    if not addr: return addr
    if "," in addr:
        tokens = addr.split(",")
        # Mask all but the first letter/digit of each part
        return ",".join([t[0] + "X"*(len(t.strip())-1) if len(t.strip()) > 1 else t for t in tokens])
    return addr[0] + "X"*(len(addr)-1) if len(addr)>1 else addr

def mask_upi(value):
    try:
        user, handle = value.split("@")
        return user[0] + "X"*(len(user)-1) + "@" + handle
    except Exception:
        return "[REDACTED_PII]"

def mask_generic(val):
    return "[REDACTED_PII]"

# --- CSV TO CSV PROCESSING --- #
def is_standalone_pii(key, value):
    if key == "phone" and PHONE_REGEX.fullmatch(str(value)): return True
    if key == "aadhar" and AADHAR_REGEX.fullmatch(str(value)): return True
    if key == "passport" and PASSPORT_REGEX.fullmatch(str(value)): return True
    if key == "upi_id" and UPI_REGEX.fullmatch(str(value)): return True
    return False

def redact_value(key, value):
    if key == "phone":
        return mask_phone(str(value))
    if key == "aadhar":
        return mask_aadhar(str(value))
    if key == "passport":
        return mask_passport(str(value))
    if key == "upi_id":
        return mask_upi(str(value))
    if key == "address":
        return mask_address(str(value))
    if key == "name":
        return mask_name(value)
    if key == "email":
        return mask_email(value)
    if key == "ip_address" or key == "device_id":
        return mask_generic(value)
    return value

def has_combinatorial_pii(data):
    found = {
        "name": "name" in data,
        "email": "email" in data,
        "address": "address" in data,
        "ip_or_device": any(k in data for k in ["ip_address", "device_id"])
    }
    # Only if two or more found in the same record
    combinatorial_fields = sum(found.values())
    return combinatorial_fields >= 2

def process_row(data_dict):
    # First: detect all standalone PII and mask if found
    pii_found = False
    record_pii_keys = set()
    redacted = data_dict.copy()

    # Standalone PII detection & redaction
    for k, v in data_dict.items():
        if is_standalone_pii(k, v):
            pii_found = True
            record_pii_keys.add(k)
            redacted[k] = redact_value(k, v)

    # Combinatorial PII detection & redaction
    has_combo = has_combinatorial_pii(data_dict)
    if has_combo:
        pii_found = True
        # Mask combinatorial fields
        if "name" in data_dict:
            redacted["name"] = mask_name(data_dict.get("name"))
        if "email" in data_dict:
            redacted["email"] = mask_email(data_dict.get("email"))
        if "address" in data_dict:
            redacted["address"] = mask_address(data_dict.get("address"))
        if "ip_address" in data_dict:
            redacted["ip_address"] = mask_generic(data_dict.get("ip_address"))
        if "device_id" in data_dict:
            redacted["device_id"] = mask_generic(data_dict.get("device_id"))

    return redacted, pii_found

def main(input_csv):
    output_csv = "redacted_output_candidate_full_name.csv"
    with open(input_csv, newline='', encoding="utf8") as fin, open(output_csv, "w", newline='', encoding="utf8") as fout:
        reader = csv.DictReader(fin)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            record_id = row["record_id"]
            data_json = row["data_json"]
            try:
                data_dict = json.loads(data_json)
            except Exception:
                writer.writerow({"record_id": record_id, "redacted_data_json": data_json, "is_pii": False})
                continue
            redacted, is_pii = process_row(data_dict)
            writer.writerow({
                "record_id": record_id,
                "redacted_data_json": json.dumps(redacted, ensure_ascii=False),
                "is_pii": str(is_pii)
            })

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        exit(1)
    main(sys.argv[1])

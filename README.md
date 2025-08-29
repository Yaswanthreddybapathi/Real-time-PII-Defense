# Real-time-PII-Defense

# 🔒 PII Detector -- Deployment Guide

This repository contains a simple yet effective **PII (Personally
Identifiable Information) Detector** built by **Ankur Chaurasia**.\
It scans datasets for sensitive information, redacts it, and marks rows
containing PII for easy analysis.

------------------------------------------------------------------------

## 📦 Requirements

-   **Kali Linux** (Python 3 comes preinstalled)\
-   Python dependencies:
    -   `csv` (standard library)\
    -   `re` (standard library)

*No extra installation required.* ✅

------------------------------------------------------------------------

## 📂 Project Structure

    project/
    ├── detector_full_Ankur_Chaurasia.py    # Main detection script
    ├── iscp_pii_dataset_-_Sheet1.csv       # Input dataset
    └── redacted_output_Ankur_Chaurasia.csv # Redacted output file

------------------------------------------------------------------------

## ▶️ Usage

Run the detector from your terminal:

``` bash
python3 detector_full_Ankur_Chaurasia.py iscp_pii_dataset_-_Sheet1.csv
```

------------------------------------------------------------------------

## 📊 Output

-   Generates a **new CSV file** →
    `redacted_output_Ankur_Chaurasia.csv`\
-   Sensitive data is replaced with `XXXX`\
-   Adds a column `is_pii`:
    -   `True` → row contains PII\
    -   `False` → no PII detected

------------------------------------------------------------------------

## ⚡ Automation (Optional)

-   **Scheduled scans** → set up a cron job\
-   **Quick execution** → wrap the script inside a shell script

------------------------------------------------------------------------

## 👤 Author

**Ankur Chaurasia**

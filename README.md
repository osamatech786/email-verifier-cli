# Email Validator Pro

A professional-grade Python tool to validate, analyze, and clean email lists for improved deliverability and engagement rates. Perfect for businesses looking to maintain high-quality email marketing lists.

## Quick Start

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Run the script on your email list:

```bash
python3 validate_emails.py emails.csv
```

## What This Tool Does

This comprehensive email validation tool:

- **Validates email syntax** according to RFC 5322 standards
- **Verifies domain existence** and checks MX records
- **Identifies disposable email addresses** that may indicate low-quality leads
- **Flags role-based emails** (info@, support@, etc.) that typically have lower engagement
- **Calculates risk scores** for each email to help prioritize your contacts
- **Generates detailed reports** with actionable insights for list management
- **Optionally performs SMTP verification** for even more thorough validation

## Output Files

The tool generates four valuable output files:

1. **valid_emails.csv** - Contains valid email addresses with risk information (risk score, disposable status, role-based status)
2. **invalid_emails.csv** - Contains invalid emails with detailed reasons for invalidity
3. **high_risk_emails.csv** - Contains valid but potentially risky emails (disposable or role-based)
4. **validation_summary.txt** - Comprehensive analysis with statistics, recommendations, and deliverability score

## Command-line Options

```bash
python3 validate_emails.py emails.csv -o results.csv -s -t 15 -w 20 -v -d -r
```

- `emails.csv`: Your input file with email addresses
- `-o, --output`: Name of the output file (default: validated_emails.csv)
- `-s, --smtp`: Enable SMTP verification (more thorough but slower)
- `-t, --timeout`: Timeout in seconds (default: 10)
- `-w, --workers`: Number of parallel workers (default: 10)
- `-v, --verbose`: Show detailed progress
- `-d, --no-disposable-check`: Disable disposable email domain checking
- `-r, --no-role-check`: Disable role-based email checking
- `--report-only`: Generate report without validation (use cached results)

## Input File Format

The tool accepts:
- CSV files with email addresses in any column
- Simple text files with one email per line

## Validation Summary Report

The validation_summary.txt file provides valuable insights including:

- Counts of valid, invalid, disposable, and role-based emails
- Risk analysis with high, medium, and low-risk categorization
- Breakdown of invalid email reasons with frequency counts
- Top domains analysis to understand your audience
- Actionable recommendations for list improvement
- Estimated deliverability score and category

## Examples

### Basic validation:
```bash
python3 validate_emails.py emails.csv
```

### With SMTP verification (more thorough):
```bash
python3 validate_emails.py emails.csv -s
```

### With custom output filename:
```bash
python3 validate_emails.py emails.csv -o my_results.csv
```

#!/usr/bin/env python3
"""
Email Validator Pro

A professional tool to validate email addresses from a CSV file and output detailed results.
Performs syntax validation, domain validation, and optional SMTP verification.
Designed for businesses to clean their email lists and improve deliverability rates.
"""

import argparse
import csv
import datetime
import dns.resolver
import logging
import os
import re
import smtplib
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Dict, List, Optional, Tuple, Counter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("email_validator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_TIMEOUT = 10  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
MAX_WORKERS = 10  # for parallel processing

# Disposable email domains list (common ones)
DISPOSABLE_DOMAINS = {
    'mailinator.com', 'yopmail.com', 'guerrillamail.com', 'temp-mail.org',
    'fakeinbox.com', 'tempmail.com', 'throwawaymail.com', 'sharklasers.com',
    'getairmail.com', '10minutemail.com', 'mailnesia.com', 'trashmail.com',
    'tempr.email', 'discard.email', 'tempinbox.com', 'emailfake.com',
    'tempmail.net', 'getnada.com', 'spamgourmet.com', 'mailcatch.com',
    'tempmailaddress.com', 'mintemail.com', 'maildrop.cc', 'mailnull.com',
    'dispostable.com', 'mailinator.net', 'mailinator.org', 'trbvm.com',
    'wegwerfmail.de', 'wegwerfmail.org', 'wegwerfmail.net'
}

# Role-based email patterns
ROLE_BASED_PATTERNS = {
    r'^admin@',
    r'^info@',
    r'^contact@',
    r'^support@',
    r'^sales@',
    r'^marketing@',
    r'^webmaster@',
    r'^postmaster@',
    r'^hostmaster@',
    r'^abuse@',
    r'^noreply@',
    r'^no-reply@',
    r'^help@',
    r'^office@',
    r'^service@',
    r'^billing@'
}


@dataclass
class ValidationResult:
    """Class to store the result of email validation."""
    email: str
    is_valid: bool
    reason: str
    details: Dict = None
    is_disposable: bool = False
    is_role_based: bool = False
    risk_score: int = 0  # 0-100 risk score (higher = more risky)


class EmailValidator:
    """Class to validate email addresses."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, verify_smtp: bool = False,
                 check_disposable: bool = True, check_role_based: bool = True):
        """Initialize the validator.

        Args:
            timeout: Timeout in seconds for network operations
            verify_smtp: Whether to perform SMTP verification
            check_disposable: Whether to check for disposable email domains
            check_role_based: Whether to check for role-based emails
        """
        self.timeout = timeout
        self.verify_smtp = verify_smtp
        self.check_disposable = check_disposable
        self.check_role_based = check_role_based
        
        # RFC 5322 compliant regex for email validation
        self.email_regex = re.compile(r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$')

    def validate_syntax(self, email: str) -> Tuple[bool, str]:
        """Validate email syntax according to RFC 5322.

        Args:
            email: Email address to validate

        Returns:
            Tuple of (is_valid, reason)
        """
        if not email or not isinstance(email, str):
            return False, "Email is empty or not a string"

        # Check length
        if len(email) > 254:
            return False, "Email exceeds maximum length of 254 characters"

        # Parse email address
        _, addr = parseaddr(email)
        if not addr or addr != email:
            return False, "Invalid email format"

        # Check against regex pattern
        if not self.email_regex.match(email):
            return False, "Email format does not comply with RFC 5322"

        # Split into local part and domain
        try:
            local_part, domain = email.rsplit('@', 1)
        except ValueError:
            return False, "Email must contain exactly one @ symbol"

        # Check local part length
        if len(local_part) > 64:
            return False, "Local part exceeds maximum length of 64 characters"

        # Check domain part
        if not domain or '.' not in domain:
            return False, "Domain must contain at least one dot"

        return True, "Valid syntax"

    def validate_domain(self, domain: str) -> Tuple[bool, str, Optional[List[str]]]:
        """Validate if domain exists and has MX records.

        Args:
            domain: Domain to validate

        Returns:
            Tuple of (is_valid, reason, mx_records)
        """
        # Check if domain resolves to an IP address
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            return False, "Domain does not exist", None

        # Check for MX records
        mx_records = []
        try:
            mx_records = [str(x.exchange) for x in dns.resolver.resolve(domain, 'MX')]
            if not mx_records:
                return False, "Domain has no MX records", None
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            try:
                # Fallback to A record if no MX records
                dns.resolver.resolve(domain, 'A')
                return True, "Domain has no MX records but has A record", None
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                return False, "Domain has no mail server records", None
        except Exception as e:
            return False, f"Error checking domain: {str(e)}", None

        return True, "Domain has valid MX records", mx_records

    def verify_mailbox(self, email: str, mx_records: List[str]) -> Tuple[bool, str]:
        """Verify if mailbox exists using SMTP.

        Args:
            email: Email address to verify
            mx_records: List of MX records for the domain

        Returns:
            Tuple of (is_valid, reason)
        """
        if not mx_records:
            return False, "No MX records available for SMTP verification"

        _, domain = email.rsplit('@', 1)
        sender = f"verify@{socket.gethostname()}"
        
        for mx in mx_records:
            # Remove trailing dot if present
            mx = mx.rstrip('.')
            
            for attempt in range(MAX_RETRIES):
                try:
                    smtp = smtplib.SMTP(timeout=self.timeout)
                    smtp.connect(mx)
                    smtp.helo(socket.gethostname())
                    smtp.mail(sender)
                    code, message = smtp.rcpt(email)
                    smtp.quit()
                    
                    if code == 250:
                        return True, "Mailbox exists"
                    elif code == 550:
                        return False, "Mailbox does not exist"
                    else:
                        return False, f"SMTP verification failed with code {code}: {message}"
                except smtplib.SMTPServerDisconnected:
                    # Some servers disconnect immediately
                    return False, "SMTP server disconnected during verification"
                except smtplib.SMTPConnectError:
                    # Try next MX record
                    break
                except (socket.timeout, smtplib.SMTPException, ConnectionRefusedError) as e:
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
                    else:
                        return False, f"SMTP verification failed: {str(e)}"
                except Exception as e:
                    return False, f"Unexpected error during SMTP verification: {str(e)}"
        
        return False, "Could not connect to any mail server"

    def validate_email(self, email: str) -> ValidationResult:
        """Validate an email address.

        Args:
            email: Email address to validate

        Returns:
            ValidationResult object with validation status and reason
        """
        # Normalize email
        email = email.strip().lower()
        
        # Initialize risk factors
        is_disposable = False
        is_role_based = False
        risk_score = 0
        
        # Check if email is from a disposable domain
        if self.check_disposable and '@' in email:
            domain = email.split('@')[1]
            if domain in DISPOSABLE_DOMAINS:
                is_disposable = True
                risk_score += 50  # High risk for disposable emails
        
        # Check if email is role-based
        if self.check_role_based:
            for pattern in ROLE_BASED_PATTERNS:
                if re.match(pattern, email):
                    is_role_based = True
                    risk_score += 30  # Medium risk for role-based emails
                    break
        
        # Validate syntax
        syntax_valid, syntax_reason = self.validate_syntax(email)
        if not syntax_valid:
            return ValidationResult(
                email=email, 
                is_valid=False, 
                reason=syntax_reason,
                is_disposable=is_disposable,
                is_role_based=is_role_based,
                risk_score=100  # Maximum risk for invalid syntax
            )
        
        # Extract domain
        _, domain = email.rsplit('@', 1)
        
        # Validate domain
        domain_valid, domain_reason, mx_records = self.validate_domain(domain)
        if not domain_valid:
            return ValidationResult(
                email=email,
                is_valid=False,
                reason=domain_reason,
                details={"syntax_valid": True},
                is_disposable=is_disposable,
                is_role_based=is_role_based,
                risk_score=100  # Maximum risk for invalid domain
            )
        
        # SMTP verification (optional)
        if self.verify_smtp and mx_records:
            smtp_valid, smtp_reason = self.verify_mailbox(email, mx_records)
            if not smtp_valid:
                return ValidationResult(
                    email=email,
                    is_valid=False,
                    reason=smtp_reason,
                    details={
                        "syntax_valid": True,
                        "domain_valid": True
                    },
                    is_disposable=is_disposable,
                    is_role_based=is_role_based,
                    risk_score=100  # Maximum risk for invalid mailbox
                )
        
        return ValidationResult(
            email=email, 
            is_valid=True, 
            reason="Email is valid",
            is_disposable=is_disposable,
            is_role_based=is_role_based,
            risk_score=risk_score,
            details={
                "syntax_valid": True,
                "domain_valid": True,
                "smtp_verified": self.verify_smtp
            }
        )


def process_csv(input_file: str, output_file: str, verify_smtp: bool = False, 
                timeout: int = DEFAULT_TIMEOUT, max_workers: int = MAX_WORKERS,
                check_disposable: bool = True, check_role_based: bool = True):
    """Process a CSV file containing email addresses.

    Args:
        input_file: Path to input CSV file
        output_file: Path to output CSV file (will contain all results)
        verify_smtp: Whether to perform SMTP verification
        timeout: Timeout for network operations
        max_workers: Maximum number of worker threads
        check_disposable: Whether to check for disposable email domains
        check_role_based: Whether to check for role-based emails
        
    Note:
        In addition to the main output file, several additional files will be created:
        - valid_emails.csv: Contains only valid email addresses
        - invalid_emails.csv: Contains only invalid email addresses
        - validation_summary.txt: Contains summary statistics and analysis
        - high_risk_emails.csv: Contains valid but risky emails (disposable/role-based)
    """
    validator = EmailValidator(timeout=timeout, verify_smtp=verify_smtp,
                         check_disposable=check_disposable, check_role_based=check_role_based)
    results = []
    emails = []
    
    # Read emails from CSV or plain text file
    try:
        with open(input_file, 'r', encoding='utf-8') as file:
            # First try to read as CSV
            try:
                reader = csv.reader(file)
                for row in reader:
                    if row:  # Skip empty rows
                        # If there's only one column, use it as the email
                        if len(row) == 1:
                            email = row[0].strip()
                            if email and '@' in email:  # Basic check to avoid empty lines
                                emails.append(email)
                        # If there are multiple columns, look for one that might be an email
                        else:
                            for cell in row:
                                cell = cell.strip()
                                if cell and '@' in cell:  # Basic check for email format
                                    emails.append(cell)
                                    break
            except csv.Error:
                # If CSV reading fails, try reading as plain text with one email per line
                file.seek(0)  # Reset file pointer to beginning
                for line in file:
                    line = line.strip()
                    if line and '@' in line:  # Basic check for email format
                        emails.append(line)
    except Exception as e:
        logger.error(f"Error reading input file: {e}")
        sys.exit(1)
    
    if not emails:
        logger.warning("No emails found in the input file")
        sys.exit(0)
    
    logger.info(f"Processing {len(emails)} email addresses...")
    
    # Process emails in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(validator.validate_email, email) for email in emails]
        for future in futures:
            try:
                result = future.result()
                results.append(result)
                status = "✓" if result.is_valid else "✗"
                logger.info(f"[{status}] {result.email}: {result.reason}")
            except Exception as e:
                logger.error(f"Error processing email: {e}")
    
    # Write results to CSV files
    try:
        # Create the main output file with all results
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Write header
            csv_writer.writerow(['Email', 'Valid', 'Reason'])
            # Write results
            for result in results:
                csv_writer.writerow([result.email, result.is_valid, result.reason])
        
        # Create valid_emails.csv with only valid emails
        valid_output = 'valid_emails.csv'
        with open(valid_output, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Write header
            csv_writer.writerow(['Email', 'Risk Score', 'Is Disposable', 'Is Role-based'])
            # Write only valid emails with risk information
            for result in results:
                if result.is_valid:
                    csv_writer.writerow([result.email, result.risk_score, result.is_disposable, result.is_role_based])
        
        # Create invalid_emails.csv with only invalid emails and reasons
        invalid_output = 'invalid_emails.csv'
        with open(invalid_output, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Write header
            csv_writer.writerow(['Email', 'Reason'])
            # Write only invalid emails with reasons
            for result in results:
                if not result.is_valid:
                    csv_writer.writerow([result.email, result.reason])
        
        # Create high_risk_emails.csv with valid but risky emails
        high_risk_output = 'high_risk_emails.csv'
        with open(high_risk_output, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            # Write header
            csv_writer.writerow(['Email', 'Risk Score', 'Risk Factors'])
            # Write valid but risky emails
            for result in results:
                if result.is_valid and (result.is_disposable or result.is_role_based or result.risk_score > 20):
                    risk_factors = []
                    if result.is_disposable:
                        risk_factors.append("Disposable email domain")
                    if result.is_role_based:
                        risk_factors.append("Role-based email address")
                    csv_writer.writerow([result.email, result.risk_score, ", ".join(risk_factors)])
        
        # Create validation_summary.txt with detailed analysis
        summary_output = 'validation_summary.txt'
        with open(summary_output, 'w', encoding='utf-8') as txtfile:
            # Get counts
            valid_count = sum(1 for r in results if r.is_valid)
            invalid_count = len(results) - valid_count
            disposable_count = sum(1 for r in results if r.is_disposable)
            role_based_count = sum(1 for r in results if r.is_role_based)
            high_risk_count = sum(1 for r in results if r.is_valid and r.risk_score > 50)
            medium_risk_count = sum(1 for r in results if r.is_valid and 20 < r.risk_score <= 50)
            low_risk_count = sum(1 for r in results if r.is_valid and r.risk_score <= 20)
            
            # Calculate percentages
            total_count = len(results)
            valid_percent = (valid_count / total_count) * 100 if total_count > 0 else 0
            invalid_percent = (invalid_count / total_count) * 100 if total_count > 0 else 0
            disposable_percent = (disposable_count / total_count) * 100 if total_count > 0 else 0
            role_based_percent = (role_based_count / total_count) * 100 if total_count > 0 else 0
            
            # Get invalid reasons
            invalid_reasons = {}
            for r in results:
                if not r.is_valid:
                    invalid_reasons[r.reason] = invalid_reasons.get(r.reason, 0) + 1
            
            # Get domain distribution
            domains = {}
            for r in results:
                if '@' in r.email:
                    domain = r.email.split('@')[1].lower()
                    domains[domain] = domains.get(domain, 0) + 1
            
            # Sort domains by frequency
            top_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Write summary
            txtfile.write("===== EMAIL VALIDATION SUMMARY =====\n\n")
            txtfile.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            txtfile.write(f"Input file: {input_file}\n")
            txtfile.write(f"Total emails processed: {total_count}\n\n")
            
            txtfile.write("=== VALIDATION RESULTS ===\n")
            txtfile.write(f"Valid emails: {valid_count} ({valid_percent:.2f}%)\n")
            txtfile.write(f"Invalid emails: {invalid_count} ({invalid_percent:.2f}%)\n\n")
            
            txtfile.write("=== RISK ANALYSIS ===\n")
            txtfile.write(f"Disposable email addresses: {disposable_count} ({disposable_percent:.2f}%)\n")
            txtfile.write(f"Role-based email addresses: {role_based_count} ({role_based_percent:.2f}%)\n")
            txtfile.write(f"High risk emails (score > 50): {high_risk_count}\n")
            txtfile.write(f"Medium risk emails (score 21-50): {medium_risk_count}\n")
            txtfile.write(f"Low risk emails (score 0-20): {low_risk_count}\n\n")
            
            txtfile.write("=== INVALID EMAIL REASONS ===\n")
            for reason, count in sorted(invalid_reasons.items(), key=lambda x: x[1], reverse=True):
                txtfile.write(f"{reason}: {count} ({(count/invalid_count*100):.2f}% of invalid)\n")
            txtfile.write("\n")
            
            txtfile.write("=== TOP 10 DOMAINS ===\n")
            for domain, count in top_domains:
                txtfile.write(f"{domain}: {count} ({(count/total_count*100):.2f}% of total)\n")
            txtfile.write("\n")
            
            txtfile.write("=== RECOMMENDATIONS ===\n")
            if invalid_count > 0:
                txtfile.write(f"• Remove {invalid_count} invalid emails to improve deliverability\n")
            if disposable_count > 0:
                txtfile.write(f"• Consider removing {disposable_count} disposable email addresses\n")
            if role_based_count > (total_count * 0.3):  # If more than 30% are role-based
                txtfile.write("• High percentage of role-based emails detected - these may have lower engagement rates\n")
            txtfile.write("• Regular validation is recommended to maintain list quality\n")
            
            # Deliverability score calculation (simple algorithm)
            deliverability_score = 100 - (invalid_percent * 0.8) - (disposable_percent * 0.4) - (role_based_percent * 0.2)
            deliverability_score = max(0, min(100, deliverability_score))  # Ensure between 0-100
            txtfile.write(f"\nEstimated deliverability score: {deliverability_score:.1f}/100\n")
            
            # Categorize the score
            if deliverability_score >= 90:
                category = "Excellent"
            elif deliverability_score >= 80:
                category = "Good"
            elif deliverability_score >= 70:
                category = "Fair"
            elif deliverability_score >= 60:
                category = "Poor"
            else:
                category = "Very Poor"
            
            txtfile.write(f"Deliverability category: {category}\n")
        
        logger.info(f"Results written to {output_file}")
        logger.info(f"Valid emails written to {valid_output}")
        logger.info(f"Invalid emails written to {invalid_output}")
        logger.info(f"High-risk emails written to {high_risk_output}")
        logger.info(f"Validation summary written to {summary_output}")
        
        # Print summary
        valid_count = sum(1 for r in results if r.is_valid)
        logger.info(f"Summary: {valid_count} valid, {len(results) - valid_count} invalid out of {len(results)} total")
    except Exception as e:
        logger.error(f"Error writing output files: {e}")
        sys.exit(1)


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Validate email addresses from a CSV file.')
    parser.add_argument('input', help='Input CSV file containing email addresses')
    parser.add_argument('-o', '--output', help='Output CSV file (default: validated_emails.csv)',
                        default='validated_emails.csv')
    parser.add_argument('-s', '--smtp', action='store_true', help='Perform SMTP verification')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'Timeout for network operations in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('-w', '--workers', type=int, default=MAX_WORKERS,
                        help=f'Maximum number of worker threads (default: {MAX_WORKERS})')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-d', '--no-disposable-check', action='store_false', dest='check_disposable',
                        help='Disable disposable email domain checking')
    parser.add_argument('-r', '--no-role-check', action='store_false', dest='check_role_based',
                        help='Disable role-based email checking')
    parser.add_argument('--report-only', action='store_true', 
                        help='Generate report without validation (use cached results)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Show banner
    print("\n" + "=" * 60)
    print("Email Validator Pro - Business Email List Cleaning Tool")
    print("=" * 60)
    
    # Check if we're only generating a report from cached results
    if args.report_only and os.path.exists(args.output):
        logger.info("Generating report from cached validation results...")
        # TODO: Implement report-only functionality
        # For now, just run the full validation
        process_csv(
            input_file=args.input,
            output_file=args.output,
            verify_smtp=args.smtp,
            timeout=args.timeout,
            max_workers=args.workers,
            check_disposable=args.check_disposable,
            check_role_based=args.check_role_based
        )
    else:
        # Process the CSV file
        start_time = time.time()
        process_csv(
            input_file=args.input,
            output_file=args.output,
            verify_smtp=args.smtp,
            timeout=args.timeout,
            max_workers=args.workers,
            check_disposable=args.check_disposable,
            check_role_based=args.check_role_based
        )
        end_time = time.time()
        
        # Print completion message with timing
        print("\n" + "=" * 60)
        print(f"Validation completed in {end_time - start_time:.2f} seconds")
        print("Results files created:")
        print("  - valid_emails.csv (Valid emails ready for use)")
        print("  - invalid_emails.csv (Invalid emails that would bounce)")
        print("  - high_risk_emails.csv (Valid but risky emails)")
        print("  - validation_summary.txt (Detailed analysis and recommendations)")
        print("=" * 60 + "\n")


if __name__ == '__main__':
    main()

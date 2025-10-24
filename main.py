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


def main():
    """Main entry point for the script."""
    # Hardcoded email for validation
    email_to_validate = "nuosama@gmail.com"

    # Show banner
    print("\n" + "=" * 60)
    print("Email Validator Pro - Single Email Validation")
    print("=" * 60)

    # Initialize the validator
    validator = EmailValidator(verify_smtp=True) # Enable SMTP verification

    logger.info(f"Validating email: {email_to_validate}")

    # Validate the email
    start_time = time.time()
    result = validator.validate_email(email_to_validate)
    end_time = time.time()

    # Print the result
    print("\n" + "=" * 60)
    print("Validation Result")
    print("-" * 60)
    print(f"Email: {result.email}")
    print(f"Is Valid: {result.is_valid}")
    print(f"Reason: {result.reason}")
    print(f"Is Disposable: {result.is_disposable}")
    print(f"Is Role-based: {result.is_role_based}")
    print(f"Risk Score: {result.risk_score}")
    if result.details:
        print("Details:")
        for key, value in result.details.items():
            print(f"  - {key}: {value}")
    print("-" * 60)
    print(f"Validation completed in {end_time - start_time:.4f} seconds")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    main()

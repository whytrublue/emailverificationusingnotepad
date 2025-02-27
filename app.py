import streamlit as st
import pandas as pd
import re
import dns.resolver
import smtplib
import socket
import time
import threading
from queue import Queue

# Set a global timeout for network operations
socket.setdefaulttimeout(5)

def is_valid_email(email):
    """Check if the email has a valid syntax."""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email)

def domain_exists(domain):
    """Check if the domain has valid MX records."""
    try:
        dns.resolver.resolve(domain, 'MX', lifetime=5)
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return False

def smtp_check(email):
    """Verify deliverability via SMTP."""
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_host = str(mx_records[0].exchange)

        with smtplib.SMTP(mx_host) as smtp:
            smtp.helo()
            smtp.mail('test@example.com')  # Change this to a valid sender email if needed
            code, _ = smtp.rcpt(email)
            return code == 250
    except Exception:
        return None  # Return None for unknown status

def process_emails(queue, results, total_emails):
    """Thread worker function to process emails from the queue."""
    current_count = 0  # Counter for the current email being processed

    while not queue.empty():
        email = queue.get()
        current_count += 1  # Increment the counter for each email processed
        st.write(f"Verifying {current_count}/{total_emails}: {email}")

        email_status = {'email': email, 'validity': "Invalid"}  # Default to Invalid

        if is_valid_email(email):
            domain = email.split('@')[-1]
            if domain_exists(domain):
                deliverable = smtp_check(email)
                if deliverable is True:
                    email_status['validity'] = "Valid"
                elif deliverable is False:
                    email_status['validity'] = "Invalid"
                else:
                    email_status['validity'] = "Unknown"
            else:
                email_status['validity'] = "Catchall"

        results.append(email_status)
        time.sleep(1)  # Add a delay between verifications

def verify_emails_in_batches(email_list, num_threads=3):
    """Verify emails using multiple threads and batch processing."""
    queue = Queue()
    results = []
    total_emails = len(email_list)

    for email in email_list:
        queue.put(email)

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=process_emails, args=(queue, results, total_emails))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return results

# Streamlit UI
st.title("📧 Email Validator")

uploaded_file = st.file_uploader("Upload a text file containing one email per line", type="txt")

if uploaded_file:
    emails = uploaded_file.read().decode("utf-8").splitlines()

    if emails:
        st.write("Starting email validation...")
        results = verify_emails_in_batches(emails)

        df = pd.DataFrame(results)
        st.write("### Validation Results:")
        st.dataframe(df)

        # Download button for CSV
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download CSV", data=csv, file_name="email_validation_results.csv", mime="text/csv")

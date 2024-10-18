"""
Email Setup and Notification Module

This module provides functions to set up email configurations and send email notifications.

Functions:
    send_email(too_email, subject, body): Sends an email to the specified recipients.
    notify_success(subject, body): Sends a success notification email.
    notify_failure(subject, body): Sends a failure notification email.
"""

# Standard library imports (for sending emails)
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Application-specific imports from our application(for email configuration details)
from App.email_configurations import (
    RECEIVER_EMAIL,
    ERROR_HANDLING_GROUP_EMAIL,
    SENDER_EMAIL,
    PASSWORD,
    SMTP_SERVER,
    SMTP_PORT
)
from Logging_package.logging_utility import log_info, log_error


def send_email_otp(receiver_email, otp):
    """Send OTP to the user's email."""
    sender_email = "komalsaikiran05@gmail.com"
    sender_password = "qlqgqoyzaynbogra"
    subject = "Your OTP"
    body = f"Your OTP is: {otp}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())


def send_email(to_email, subject, body):
    """
    Sends an email to the specified recipients.

    :param to_email: List of recipient email addresses.
    :param subject: Subject of the email.
    :param body: Body of the email.
    :return: bool indicating success or failure of email sending.
    """
    if not to_email or len(to_email) == 0:
        log_error("No recipient email provided.")
        return False  # Indicate failure

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = ", ".join(to_email)
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
            log_info(f"Email sent successfully to: {', '.join(to_email)} with subject: {subject}.")
            return True  # Indicate success
    except smtplib.SMTPException as smtp_err:
        log_error(f"SMTP error occurred: {str(smtp_err)}")
    except Exception as e:
        log_error(f"An error occurred while sending email: {str(e)}")

    return False  # Indicate failure


def notify_success(subject, details):
    """
    Sends a success notification email with detailed information.

    :param subject: Subject of the success email.
    :param details: Detailed information to include in the email body.
    """
    body = f"Successful!\n\nDetails:\n********************************************\n{details}"
    try:
        if send_email(RECEIVER_EMAIL, subject, body):
            log_info("Success notification email sent.")
        else:
            log_error("Failed to send success notification email.")
    except Exception as e:
        log_error(f"Error in notifying success: {str(e)}")


def notify_failure(subject, details):
    """
    Sends a failure notification email with detailed information.

    :param subject: Subject of the failure email.
    :param details: Detailed information to include in the email body.
    """
    body = f"Failure!\n\nDetails:\n********************************************\n{details}"
    try:
        if send_email(ERROR_HANDLING_GROUP_EMAIL, subject, body):
            log_info("Failure notification email sent.")
        else:
            log_error("Failed to send failure notification email.")
    except Exception as e:
        log_error(f"Error in notifying failure: {str(e)}")


def send_email_notification(message):
    """
    Sends an email notification with the provided message.

    :param message: The message to be included in the email body.
    :return: bool indicating success or failure of email sending.
    """
    recipient_email = RECEIVER_EMAIL[0]
    subject = "Registered Users Details"

    try:
        if send_email([recipient_email], subject, message):
            log_info(f"Email notification sent to: {recipient_email} with subject: {subject}.")
            return True  # Indicate success
        else:
            log_error("Failed to send email notification.")
    except Exception as e:
        log_error(f"Error in sending email notification: {str(e)}")

    return False  # Indicate failure

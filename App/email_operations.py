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
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Application-specific imports from our application(for email configuration details)
from App.email_configurations import (
    RECEIVER_EMAIL,
    ERROR_HANDLING_GROUP_EMAIL,
    SENDER_EMAIL,
    PASSWORD,
    SMTP_SERVER,
    SMTP_PORT, ADMIN_EMAIL
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
        return False

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
            return True
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
            return True
        else:
            log_error("Failed to send email notification.")
    except Exception as e:
        log_error(f"Error in sending email notification: {str(e)}")

    return False


# email_operations.py

def generate_train_email_body(train_name, train_number, source, destination, departure_time, arrival_time,
                              available_seats, total_seats, creation_time):
    """
    Generate the email body for the new train added notification.
    """
    return (f"Dear Team A new train has been added Successfully:\n"
            f"-----------------------------------\n"
            f"Train Name: {train_name}\n"
            f"Train Number: {train_number}\n"
            f"Source: {source}\n"
            f"Destination: {destination}\n"
            f"Departure Time: {departure_time}\n"
            f"Arrival Time: {arrival_time}\n"
            f"Available Seats: {available_seats}\n"
            f"Total Seats: {total_seats}\n"
            f"Added at: {creation_time} (IST)\n"
            f"-----------------------------------\n"
            f"Best Regards,\n"
            f"Train Management System")


def fetch_train_email_body(train_records, total_count):
    """
    Generate the email body for train records.

    Args:
        train_records (list): A list of train record dictionaries.
        total_count (int): Total count of train records found.

    Returns:
        str: Formatted email body with train details.
    """
    email_body = f"Train Records Fetched (Total Count: {total_count}):\n\n"

    for train in train_records:
        email_body += (
            f"Train Id: {train['train_id']}\n"
            f"Train Name: {train['train_name']}\n"
            f"Train Number: {train['train_number']}\n"
            f"Source: {train['source']}\n"
            f"Destination: {train['destination']}\n"
            f"Departure Time: {train['departure_time']}\n"
            f"Arrival Time: {train['arrival_time']}\n"
            f"Total Seats: {train['total_seats']}\n"  
            f"Available Seats: {train['available_seats']}\n"
            f"Waiting List Count: {train['waiting_list_count']}\n"  
            f"-----------------------------------\n"
        )
    return email_body


def construct_train_email_body(train_name, train_number, source, destination,
                               departure_time, arrival_time, total_seats,
                               available_seats, waiting_list_count, timestamp):
    """
    Construct the email body for train notifications.

    Args:
        train_name (str): Name of the train.
        train_number (str): Unique identifier of the train.
        source (str): Starting point of the train.
        destination (str): Destination of the train.
        departure_time (str): Scheduled departure time of the train.
        arrival_time (str): Scheduled arrival time of the train.
        total_seats (int): Total number of seats in the train.
        available_seats (int): Number of available seats.
        waiting_list_count (int): Number of users in the waiting list.
        timestamp (str): Time when the record was added or updated.

    Returns:
        str: Formatted email body with train details.
    """
    email_body = (
        f"Dear Admin,\n\n"
        f"We are pleased to inform you that the train details have been updated.\n\n"
        f"**Train Details:**\n"
        f"- **Train Name:** {train_name}\n"
        f"- **Train Number:** {train_number}\n"
        f"- **Source:** {source}\n"
        f"- **Destination:** {destination}\n"
        f"- **Departure Time:** {departure_time}\n"
        f"- **Arrival Time:** {arrival_time}\n"
        f"- **Total Seats:** {total_seats}\n"
        f"- **Available Seats:** {available_seats}\n"
        f"- **Waiting List Count:** {waiting_list_count}\n\n"
        f"**Record Timestamp:** {timestamp}\n\n"
        f"Best Regards,\n"
        f"Train Management System"
    )
    return email_body


def prepare_and_send_email(action, train_details, operation_time, email):
    """
    Prepares and sends a detailed email notification for the action performed on the trains.

    :param action: The action performed (e.g., 'deletion').
    :param train_details: A list of train names that were deleted.
    :param operation_time: The time the operation took place.
    :param email: The email address to send the notification to.
    """
    email_subject = f"Train {action.capitalize()} Notification"

    email_body = f"""
    Dear Admin,

    The following trains were {action} successfully:

    {', '.join(train_details)}

    Time of operation: {operation_time}

    Best Regards,
    Train Management System
    """
    send_email(to_email=[email], subject=email_subject, body=email_body)


def send_booking_confirmation_email(recipient, booking_id, user_id, train_id, seats_booked, booking_time):
    """Send a booking confirmation email."""
    subject = "Booking Confirmation"
    body = (
        f"Dear Customer,\n\n"
        f"Your booking has been confirmed!\n"
        f"Booking ID: {booking_id}\n"
        f"User ID: {user_id}\n"
        f"Train ID: {train_id}\n"
        f"Seats Booked: {seats_booked}\n"
        f"Booking Time: {booking_time}\n\n"
        "Thank you for booking with us!\n"
        "Safe travels!\n"
    )

    send_email(to_email=[recipient], subject=subject, body=body)


def generate_route_email_body(train_name, train_number, station_name, arrival_time, departure_time, creation_time,
                              origin, destination):
    """
    Generate the email body for the new train route added notification.

    Parameters:
    - train_name: The name of the train.
    - train_number: The number of the train.
    - station_name: The station where the route is added.
    - arrival_time: The arrival time of the train at the station.
    - departure_time: The departure time of the train from the station.
    - creation_time: The time when the route was added.
    - origin: The starting point of the train route.
    - destination: The ending point of the train route.

    Returns:
    - str: Formatted email body.
    """
    return (f"Dear Team,\n\n"
            f"A new train route has been added successfully:\n"
            f"-----------------------------------\n"
            f"Train Name: {train_name}\n"
            f"Train Number: {train_number}\n"
            f"Station Name: {station_name}\n"
            f"Arrival Time: {arrival_time}\n"
            f"Departure Time: {departure_time}\n"
            f"Origin: {origin}\n"
            f"Destination: {destination}\n"
            f"Added at: {creation_time} (IST)\n"
            f"-----------------------------------\n"
            f"Best Regards,\n"
            f"Train Management System")


def generate_fetch_email_body(routes, creation_time, total_count):
    """Generate the email body for fetched train routes."""
    body = f"Train routes fetched at {creation_time}:\n"
    body += f"Total Count: {total_count}\n\n"
    for route in routes:
        body += f"Dear Team,\n\n"
        body += f"Fetched Train Details Successfully:\n"
        body += f"-----------------------------------\n"
        body += f"Route ID: {route.get('route_id', 'N/A')}\n"
        body += f"Train Number: {route['train_number']}\n"
        body += f"Train Name: {route['train_name']}\n"
        body += f"Station Name: {route['station_name']}\n"
        body += f"Arrival Time: {route['arrival_time']}\n"
        body += f"Departure Time: {route['departure_time']}\n"
        body += f"Origin: {route['origin']}\n"
        body += f"Destination: {route['destination']}\n\n"
        body += f"Best Regards,\n"
        body += f"Train Management System"

    return body


def notify_deletion(train_number, station_name, deletion_status, email_time, formatted_deletion_time):
    """
    Generate the email body for the deletion of a train route and send the notification.

    Parameters:
    - train_number (str): The number of the train.
    - station_name (str): The station name where the route is deleted.
    - deletion_status (str): The status of the deletion ("success" or "error").
    - email_time (datetime): The time when the email notification is sent.
    - formatted_deletion_time (str): The time when the deletion occurred, formatted as a string.
    """
    # Format the email time
    formatted_email_time = email_time.strftime("%Y-%m-%d %H:%M:%S")

    # Construct the email body
    email_body = (
        f"Dear Team,\n\n"
        f"The following train route deletion details:\n"
        f"-----------------------------------\n"
        f"Train Number: {train_number}\n"
        f"Station Name: {station_name}\n"
        f"Deleted at: {formatted_deletion_time} (IST)\n"  
        f"Notification Sent at: {formatted_email_time} (IST)\n"  
        f"Status: {'Deletion Successful' if deletion_status == 'success' else 'Deletion Failed'}\n"
        f"-----------------------------------\n"
        f"Best Regards,\n"
        f"Train Management System"
    )

    subject = f"Train Route Deletion Status: {deletion_status.capitalize()}"

    send_email(
        to_email=ADMIN_EMAIL,
        subject=subject,
        body=email_body
    )

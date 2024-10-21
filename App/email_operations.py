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
    SMTP_PORT, ADMIN_EMAIL
)
from Logging_package.logging_utility import log_info, log_error


def send_email_otp(receiver_email, otp):
    """
    Send an OTP to the user's email address.

    Args:
        receiver_email (str): The email address to which the OTP will be sent.
        otp (str): The one-time password to send.

    Raises:
        Exception: Raises an exception if sending the email fails.
    """
    sender_email = SENDER_EMAIL
    sender_password = PASSWORD
    subject = "Your OTP"
    body = f"Your OTP is: {otp}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        log_info(f"OTP sent to {receiver_email}")

    except Exception as e:
        log_error(f"Failed to send OTP to {receiver_email}: {str(e)}")
        raise


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

    return False


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

    :param train_name: (str) Name of the train.
    :param train_number: (str) Unique identifier of the train.
    :param source: (str) Starting point of the train.
    :param destination: (str) Destination of the train.
    :param departure_time: (str) Scheduled departure time of the train.
    :param arrival_time: (str) Scheduled arrival time of the train.
    :param available_seats: (int) Number of available seats on the train.
    :param total_seats: (int) Total number of seats on the train.
    :param creation_time: (str) Time when the train record was created.

    :return: (str) Formatted email body with train details.
    """

    try:
        email_body = (f"Dear Team,\n\n"
                      f"A new train has been added successfully:\n"
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
        return email_body

    except Exception as e:
        log_error(f"Error generating train email body: {str(e)}")
        raise


def fetch_train_email_body(train_records, total_count):
    """
       Generate the email body for train records.

    :param train_records: (list) A list of train record dictionaries.
    :param total_count: (int) Total count of train records found.
    :return: (str) Formatted email body with train details.
    """
    try:
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

    except Exception as e:
        log_error(f"Error generating email body for fetched train records: {str(e)}")
        raise


def construct_train_email_body(train_name, train_number, source, destination,
                               departure_time, arrival_time, total_seats,
                               available_seats, waiting_list_count, timestamp):
    """
     Construct the email body for train notifications.

    :param train_name: (str) Name of the train.
    :param train_number: (str) Unique identifier of the train.
    :param source: (str) Starting point of the train.
    :param destination: (str) Destination of the train.
    :param departure_time: (str) Scheduled departure time of the train.
    :param arrival_time: (str) Scheduled arrival time of the train.
    :param total_seats: (int) Total number of seats in the train.
    :param available_seats: (int) Number of available seats.
    :param waiting_list_count: (int) Number of users in the waiting list.
    :param timestamp: (str) Time when the record was added or updated.
    :return:
    (str) Formatted email body with train details.
    """

    try:
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

    except Exception as e:
        log_error(f"Error constructing email body for train {train_number}: {str(e)}")
        raise


def prepare_and_send_email(action, train_details, operation_time, email):
    """
    Prepares and sends a detailed email notification for the action performed on the trains.

    :param action:(str) The action performed (e.g., 'deletion').
    :param train_details:(list) A list of train names that were deleted.
    :param operation_time:(str) The time the operation took place.
    :param email:(str) The email address to send the notification to.
    Returns: None
    """
    try:
        email_subject = f"Train {action.capitalize()} Notification"

        train_list = ', '.join(train_details) if train_details else "No trains involved"

        email_body = f"""
            Dear Admin,

            The following trains were {action} successfully:

            {train_list}

            Time of operation: {operation_time}

            Best Regards,
            Train Management System
            """

        send_email(to_email=[email], subject=email_subject, body=email_body)

        log_info(f"Email notification for train {action} sent to {email} at {operation_time}.")

    except Exception as e:
        log_error(f"Failed to send train {action} notification email to {email}: {str(e)}")
        raise


def send_booking_confirmation_email(recipient, booking_id, user_id, train_id, seats_booked, booking_time):
    """
     Send a booking confirmation email to the customer.

    :param recipient: (str): Email address of the recipient.
    :param booking_id: (str): The booking ID.
    :param user_id: (str): The user ID associated with the booking.
    :param train_id: (str): The train ID for the booking.
    :param seats_booked: (int): Number of seats booked.
    :param booking_time: (str): Time when the booking was made.
    :return: None
    """
    try:
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
        log_info(f"Booking confirmation email sent successfully to {recipient} for booking ID {booking_id}.")

    except Exception as e:
        log_error(f"Failed to send booking confirmation email to {recipient}: {str(e)}")
        raise


def generate_route_email_body(train_name, train_number, station_name, arrival_time, departure_time, creation_time,
                              origin, destination):
    """
      Generate the email body for the new train route added notification.

    :param train_name: (str) The name of the train.
    :param train_number: (str) The number of the train.
    :param station_name: (str) The station where the route is added.
    :param arrival_time: (str) The arrival time of the train at the station.
    :param departure_time: (str) The departure time of the train from the station.
    :param creation_time: (str) The time when the route was added.
    :param origin: (str) The starting point of the train route.
    :param destination: (str) The ending point of the train route.

    :return: str Formatted email body for route addition notification.
    """
    try:
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
    except Exception as e:
        log_error(f"Error generating route email body: {str(e)}")
        raise


def generate_fetch_email_body(routes, creation_time, total_count):
    """
    Generate the email body for fetched train routes

    :param routes: list of dictionaries containing train route details
    :param creation_time: timestamp when the routes were fetched
    :param total_count: total number of routes fetched
    :return: a formatted string containing the fetched train route details
    """

    try:
        body = f"Train routes fetched at {creation_time}:\n"
        body += f"Total Count: {total_count}\n\n"

        for route in routes:
            body += f"Dear Team,\n\n"
            body += f"Fetched Train Details Successfully:\n"
            body += f"-----------------------------------\n"
            body += f"Route ID: {route.get('route_id', 'N/A')}\n"
            body += f"Train Number: {route.get('train_number', 'N/A')}\n"
            body += f"Train Name: {route.get('train_name', 'N/A')}\n"
            body += f"Station Name: {route.get('station_name', 'N/A')}\n"
            body += f"Arrival Time: {route.get('arrival_time', 'N/A')}\n"
            body += f"Departure Time: {route.get('departure_time', 'N/A')}\n"
            body += f"Origin: {route.get('origin', 'N/A')}\n"
            body += f"Destination: {route.get('destination', 'N/A')}\n\n"
            body += "Best Regards,\nTrain Management System\n\n"

        return body

    except Exception as e:
        log_error(f"Error generating fetch email body: {str(e)}")
        raise


def notify_deletion(train_number, station_name, deletion_status, email_time, formatted_deletion_time):
    """
       Generate the email body for the deletion of a train route and send the notification.

    :param train_number: (str) The number of the train.
    :param station_name: (str)  The station name where the route is deleted.
    :param deletion_status: (str) The status of the deletion ("success" or "error").
    :param email_time: (datetime) The time when the email notification is sent.
    :param formatted_deletion_time: (str) The time when the deletion occurred, formatted as a string.
    :return:
    """

    try:
        formatted_email_time = email_time.strftime("%Y-%m-%d %H:%M:%S")
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

    except Exception as err:
        log_error(f"Error generating notify deletion email body: {str(err)}")
        raise


def generate_booking_email_body(booking_id, username, train_number, train_name, seats_booked, seat_preference,
                                booking_date, travel_date, source, destination, creation_time):
    """
    Generates the email body for the booking confirmation notification.

    :param train_number: Number of the train for which the booking was made.
    :param booking_id: Unique identifier for the booking.
    :param username: Name of the user who made the booking.
    :param train_name: Name of the train for which the booking was made.
    :param seats_booked: Number of seats booked by the user.
    :param seat_preference: Seat preference selected by the user (if any).
    :param booking_date: The date when the booking was created.
    :param travel_date: The date of the scheduled travel.
    :param source: The departure station.
    :param destination: The arrival station.
    :param creation_time: The timestamp when the booking was created.
    :return: A formatted email body with booking details.
    """

    try:
        email_body = (
            f"Dear {username},\n\n"
            f"Your booking has been successfully created:\n"
            f"-----------------------------------\n"
            f"Booking ID: {booking_id}\n"
            f"User Name: {username}\n"
            f"Train Number: {train_number}\n"
            f"Train Name: {train_name}\n"
            f"Seats Booked: {seats_booked}\n"
            f"Seat Preference: {seat_preference}\n"
            f"Booking Date: {booking_date}\n"
            f"Travel Date: {travel_date}\n"
            f"Source: {source}\n"
            f"Destination: {destination}\n"
            f"Created at: {creation_time} (IST)\n"
            f"-----------------------------------\n"
            f"Thank you for choosing our services.\n"
            f"Best Regards,\n"
            f"Railway Booking System"
        )

        # Send the email with the generated email body
        subject = f"Booking Confirmation {booking_id}"
        send_email(
            subject=subject,
            body=email_body,
            to_email=ADMIN_EMAIL  # Optionally add the user's email as well
        )

    except Exception as e:
        log_error(f"Error generating booking email body: {str(e)}")
        raise


def handle_error(exception, message_prefix, detailed_message):
    """
     Handles errors by logging the exception, sending an email notification, and optionally
    returning or logging a secondary error in case of a failure during error handling.

    :param exception:(Exception) The exception that was raised.
    :param message_prefix:(str) A prefix for the error message, usually indicating the context.
    :param detailed_message:(str) A detailed message explaining the error context.
    :return: (str or None) Returns the secondary error message if an error occurs during error handling,
                      otherwise returns None.
    """
    try:
        error_message = f"{message_prefix}: {exception}"
        log_error(f"{detailed_message}: {error_message}")

        send_email(
            subject="Booking Error Notification",
            body=f"An error occurred: {error_message}",
            to_email=ERROR_HANDLING_GROUP_EMAIL
        )

    except Exception as err:
        log_error(f"Error occurred while handling another error: {str(err)}")
        return err


def generate_booking_list_email_body(bookings, total_count):
    """
    Generates the email body for the bookings fetch success.

    :param bookings: List of booking dictionaries.
    :param total_count: Total number of bookings found.
    :return: A formatted email body with booking details.
    """
    try:
        email_body = (
            f"Dear Admin,\n\n"
            f"Here are the details of the bookings fetched:\n"
            f"-----------------------------------\n"
            f"Total Bookings: {total_count}\n\n"
        )

        for booking in bookings:
            # Safeguard for booking details
            booking_id = booking.get('booking_id', 'N/A')
            traveler_name = booking.get('traveler_name', 'N/A')
            train_name = booking.get('train_name', 'N/A')
            travel_date = booking.get('travel_date', 'N/A')
            seats_booked = booking.get('seats_booked', 'N/A')

            email_body += (
                f"Booking ID: {booking_id}, "
                f"User: {traveler_name}, "
                f"Train: {train_name}, "
                f"Travel Date: {travel_date}, "
                f"Seats Booked: {seats_booked}\n"
            )

        email_body += (
            f"-----------------------------------\n"
            f"Best Regards,\n"
            f"Railway Booking System"
        )

        return email_body

    except Exception as e:
        log_error(f"Error generating booking list email body: {str(e)}")
        raise


def send_error_email(subject, error_message):
    """
    Sends an error notification email with the provided subject and error message.

    :param subject: The subject of the email.
    :param error_message: Detailed error message to be included in the email body.
    :return: None
    """
    try:
        email_body = (
            f"Dear Admin,\n\n"
            f"An error occurred during the operation:\n"
            f"-----------------------------------\n"
            f"Error Details: {error_message}\n"
            f"-----------------------------------\n"
            f"Please check the logs for further investigation.\n"
            f"Best Regards,\n"
            f"Booking System"
        )

        send_email(to_email=ERROR_HANDLING_GROUP_EMAIL, subject=subject, body=email_body)

    except Exception as e:
        log_error(f"Failed to send error email: {str(e)}")


def generate_update_booking_email_body(booking_id, username, train_number, train_name, seats_booked, seat_preference,
                                       booking_date, travel_date, source, destination, formatted_updated_time):
    """
    Generates the email body for the booking update notification.

    :param booking_id: Unique identifier for the booking.
    :param username: Name of the user who made the booking.
    :param train_number: Number of the train for which the booking was made.
    :param train_name: Name of the train for which the booking was made.
    :param seats_booked: Number of seats booked by the user.
    :param seat_preference: Seat preference selected by the user (if any).
    :param booking_date: The date when the booking was created.
    :param travel_date: The date of the scheduled travel.
    :param source: The departure station.
    :param destination: The arrival station.
    :param formatted_updated_time: The timestamp when the booking was last updated.
    :return: A formatted email body with booking update details.
    """
    try:
        email_body = (
            f"Dear {username},\n\n"
            f"Your booking has been successfully updated:\n"
            f"-----------------------------------\n"
            f"Booking ID: {booking_id}\n"
            f"User Name: {username}\n"
            f"Train Number: {train_number}\n"
            f"Train Name: {train_name}\n"
            f"Seats Booked: {seats_booked}\n"
            f"Seat Preference: {seat_preference}\n"
            f"Booking Date: {booking_date}\n"
            f"Travel Date: {travel_date}\n"
            f"Source: {source}\n"
            f"Destination: {destination}\n"
            f"Updated at: {formatted_updated_time} (IST)\n"
            f"-----------------------------------\n"
            f"Thank you for choosing our services.\n"
            f"Best Regards,\n"
            f"Railway Booking System"
        )

        subject = f"Booking Update Confirmation {booking_id}"
        send_email(
            subject=subject,
            body=email_body,
            to_email=ADMIN_EMAIL
        )

    except Exception as e:
        log_error(f"Error generating booking update email body: {str(e)}")
        raise

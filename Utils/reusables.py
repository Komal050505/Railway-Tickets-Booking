# Standard Library Imports
import threading
import time
from datetime import datetime, timedelta
from functools import wraps

# Third-Party Library Imports
from flask import jsonify, request
from sqlalchemy.exc import SQLAlchemyError
import pyttsx3

# Project-Specific Imports
from App.constants import VOICE_NOTIFICATIONS_ENABLED
from Db_connections.configurations import session
from Logging_package.logging_utility import log_error, log_info
from Models.tables import OTPStore


engine = pyttsx3.init()


def speak(message):
    """
        Convert the given message to speech if voice notifications are enabled.

        This function checks if voice notifications are enabled and, if so,
        it runs a separate thread to convert the provided message into speech
        using the pyttsx3 engine. It handles exceptions that may occur during
        the speech synthesis process, logging errors and notifying users as needed.

        :param message: The message to be spoken aloud. It should be a string
                        containing the text to convert to speech.
        :return: None
        """
    try:

        if VOICE_NOTIFICATIONS_ENABLED:  # Check if voice notifications are enabled
            def speak_in_thread(msg):
                """
                Convert the provided message to speech in a separate thread.

                This function uses the pyttsx3 engine to synthesize speech from the
                provided message. It handles any exceptions that may occur during
                the speech synthesis process and logs the error.

                :param msg: The message to be spoken aloud. It should be a string
                            containing the text to convert to speech.
                :return: None
                """
                try:
                    engine.say(msg)
                    engine.runAndWait()  # This should be called in the same thread
                except Exception as e:
                    log_error(f"Error in text-to-speech conversion: {str(e)}")
            # Create a thread to handle speaking
            thread = threading.Thread(target=speak_in_thread, args=(message,))
            thread.start()
    except Exception as err:
        log_error(f"Error in speak function: {str(err)}")


# It is Universal OTP Decorator used for all api's

def otp_required(func):
    """
     Decorator to validate OTP (One-Time Password) for user authentication.

     This decorator checks if the request payload contains the required 'email' and 'otp' fields, validates the OTP
     against the stored record for the given email, and ensures that the OTP has not expired.

     If the validation is successful, it proceeds to call the wrapped function. If the validation fails, it logs the
     error and returns a relevant error message and HTTP status code.

     :param func:(callable) The function to be wrapped. This function should be executed if the OTP validation is successful.

     :return:(callabe) The wrapped function if OTP validation is successful,otherwise returns an error response.

    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        """
        Wrapper function to validate the OTP and execute the wrapped function.

        This function processes the request to extract the required 'email' and
        'otp' from the JSON payload, checks their validity, and allows the
        wrapped function to be executed if the OTP validation is successful.

        :param args:  (*args) Positional arguments passed to the wrapped function.
        :param kwargs:(**kwargs) Keyword arguments passed to the wrapped function.

        :return:(callable) The result of the wrapped function if OTP validation
                  is successful, otherwise returns an error response in
                  JSON format.
        """
        payload = request.get_json()
        email = None
        try:
            if not payload or 'email' not in payload or 'otp' not in payload:
                log_error("OTP validation failed: Email and OTP are required.")
                return jsonify({"error": "Email and OTP are required."}), 400

            email = payload['email']
            otp = payload['otp']

            otp_record = session.query(OTPStore).filter_by(email=email).order_by(OTPStore.timestamp.desc()).first()

            if not otp_record:
                log_error(f"OTP validation failed: No OTP generated for {email}.")
                return jsonify({"error": "No OTP generated for this email."}), 400

            # Check if OTP is expired (valid for 5 minutes)
            if datetime.now() - otp_record.timestamp > timedelta(minutes=10):
                log_error(f"OTP validation failed: OTP for {email} has expired.")
                return jsonify({"error": "OTP has expired."}), 400

            if otp != otp_record.otp:
                log_error(f"OTP validation failed: Invalid OTP for {email}.")
                return jsonify({"error": "Invalid OTP."}), 400

            log_info(f"OTP validation successful for {email}.")
            return func(*args, **kwargs)

        except SQLAlchemyError as db_error:
            session.rollback()
            log_error(f"Database error while validating OTP for {email}: {db_error}")
            return jsonify({"error": "Internal server error", "details": str(db_error)}), 500

        except Exception as e:
            log_error(f"Unexpected error while validating OTP for {email}: {e}")
            return jsonify({"error": "Internal server error", "details": str(e)}), 500

        finally:
            session.close()

    return wrapper


def generate_train_search_results(train_records):
    """
    Convert a list of train records into a dictionary format for JSON response.

    Args:
        train_records (list): List of Train objects.

    Returns:
        list: List of dictionaries containing train details.
    """
    results = []
    for train in train_records:
        result = {
            "train_id": train.train_id,
            "train_name": train.train_name,
            "train_number": train.train_number,
            "source": train.source,
            "destination": train.destination,
            "departure_time": train.departure_time,
            "arrival_time": train.arrival_time,
            "total_seats": getattr(train, 'total_seats', None),  # Using getattr for safety
            "available_seats": getattr(train, 'available_seats', None),
            "waiting_list_count": getattr(train, 'waiting_list_count', 0)
        }
        results.append(result)
    return results


def validate_time_format(time_str):
    """
    Validate the time format (HH:MM) for departure and arrival times.

    Args:
        time_str (str): Time string to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        time.strptime(time_str, "%H:%M")
        return True
    except ValueError:
        return False


def validate_booking_data(data):
    """
     Validate the provided booking data to ensure it meets the necessary
     criteria for processing a booking.

     This function checks if the required fields in the booking data are
     present and valid. It may include validations for dates, times,
     customer details, and any specific requirements for the booking.

     :param data:(dict) A dictionary containing the booking information.
                     Expected keys may include 'customer_name', 'date',
                     'time', 'number_of_guests', etc
     :return: bool: True if the booking data is valid, otherwise False.
             dict: A dictionary containing error messages for invalid fields,
                   if any. An empty dictionary indicates that there are
                   no validation errors.
     """
    required_fields = ['user_id', 'train_id', 'seats_booked', 'travel_date', 'source', 'destination']
    try:
        for field in required_fields:
            if field not in data or not data[field]:
                return False, f"{field} is missing or empty."

        try:
            datetime.strptime(data['travel_date'], '%Y-%m-%d')
        except ValueError:
            return False, "Invalid date format for travel_date. Use YYYY-MM-DD."
    except Exception as err:
        return jsonify(f"Exception error occurred and error is {err}")
    return True, None

import threading
from datetime import datetime, timedelta
from functools import wraps

import pyttsx3  # Correctly import pyttsx3
from flask import jsonify, request
from sqlalchemy.exc import SQLAlchemyError

from App.constants import VOICE_NOTIFICATIONS_ENABLED
from Db_connections.configurations import session
from Logging_package.logging_utility import log_error, log_info
from Models.tables import OTPStore

# Initialize the TTS engine
engine = pyttsx3.init()


def set_voice_notifications_enabled(enabled: bool):
    """Set the state of voice notifications."""
    global VOICE_NOTIFICATIONS_ENABLED  # Declare as global to modify it
    VOICE_NOTIFICATIONS_ENABLED = enabled


def speak(message):
    if VOICE_NOTIFICATIONS_ENABLED:  # Check if voice notifications are enabled
        def speak_in_thread(msg):
            engine.say(msg)
            engine.runAndWait()  # This should be called in the same thread

        # Create a thread to handle speaking
        thread = threading.Thread(target=speak_in_thread, args=(message,))
        thread.start()


# It is Universal OTP Decorator used for all api's

def otp_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        payload = request.get_json()

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
            if datetime.now() - otp_record.timestamp > timedelta(minutes=5):
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
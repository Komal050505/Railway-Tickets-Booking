import time
from random import random
from urllib import request

from flask import Flask, jsonify, request, session
from datetime import datetime
import pytz
from sqlalchemy.exc import SQLAlchemyError

from App.email_configurations import RECEIVER_EMAIL
from App.email_operations import notify_failure, send_email, notify_success, send_email_notification, send_email_otp
from Db_connections.configurations import session
from Logging_package.logging_utility import log_info, log_debug, log_warning, log_error
from Models.tables import Booking, Train, Railway_User, OTPStore
import pyttsx3
import threading
from Utils.reusables import speak, otp_required
import requests
import psutil
import random

app = Flask(__name__)

engine = pyttsx3.init()


# ------------------------------------CHECKS OTHER APIS PERFORMANCES ---------------------------------------------------

@app.route('/check-api-performance', methods=['POST'])
def check_api_performance():
    try:
        payload = request.get_json()
        if not payload or 'url' not in payload or 'method' not in payload:
            error_message = "URL and Method are required to check API performance."
            log_error(error_message)
            return jsonify({"error": error_message}), 400

        url = payload['url']
        method = payload['method'].upper()
        data = payload.get('data', {})

        headers = {'Content-Type': 'application/json'}

        initial_cpu = psutil.cpu_percent()
        initial_memory = psutil.virtual_memory().used
        start_time = time.time()

        if method == 'GET':
            response = requests.get(url)
        elif method == 'POST':
            response = requests.post(url, json=data, headers=headers)
        elif method == 'PUT':
            response = requests.put(url, json=data, headers=headers)
        elif method == 'DELETE':
            response = requests.delete(url)
        else:
            error_message = f"Unsupported HTTP method: {method}"
            log_error(error_message)
            return jsonify({"error": error_message}), 400

        response.raise_for_status()
        end_time = time.time()
        execution_time = end_time - start_time
        final_cpu = psutil.cpu_percent()
        final_memory = psutil.virtual_memory().used
        memory_used = final_memory - initial_memory

        performance_metrics = {
            "url": url,
            "status_code": response.status_code,
            "response_time": execution_time,
            "initial_cpu_usage": initial_cpu,
            "final_cpu_usage": final_cpu,
            "memory_used": memory_used,
            "response": response.json() if response.content else {}
        }

        log_info(f"API performance check successful for URL: {url}")
        email_subject = f"API Performance Check Successful for URL: {url}"
        email_content = f"API Performance Metrics for URL: {url}\n\n" + \
                        f"Status Code: {performance_metrics['status_code']}\n" + \
                        f"Response Time: {performance_metrics['response_time']} seconds\n" + \
                        f"Initial CPU Usage: {performance_metrics['initial_cpu_usage']}%\n" + \
                        f"Final CPU Usage: {performance_metrics['final_cpu_usage']}%\n" + \
                        f"Memory Used: {performance_metrics['memory_used']} bytes\n"

        send_email(RECEIVER_EMAIL, email_subject, email_content)

        return jsonify(performance_metrics), 200

    except requests.exceptions.RequestException as e:
        error_message = f"Failed to call the target API: {str(e)}"
        log_error(error_message)
        send_email(RECEIVER_EMAIL, "API Performance Check Failed", error_message)
        return jsonify({"error": error_message}), 500

    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        log_error(error_message)
        send_email(RECEIVER_EMAIL, "API Performance Check Error", error_message)
        return jsonify({"error": error_message}), 500

    finally:
        log_info("End of check_api_performance function")


# ---------------------------------------- OTP GENERATOR API -----------------------------------------------------------

@app.route('/generate-otp', methods=['POST'])
def generate_otp():
    """
    Generates an OTP and sends it to the user's email, storing the OTP in PostgreSQL.
    """
    email = None
    try:
        payload = request.get_json()
        if not payload or 'email' not in payload:
            log_error("Email is required to generate OTP.")
            return jsonify({"error": "Email is required to generate OTP."}), 400

        email = payload['email']
        otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
        timestamp = datetime.now()

        new_otp = OTPStore(email=email, otp=str(otp), timestamp=timestamp)
        session.add(new_otp)
        session.commit()

        log_info(f"Generated OTP for {email}: {otp}")

        send_email_otp(email, otp)

        return jsonify({"message": f"OTP sent to {email}",
                        "otp": f"OTP is {otp}"}), 200

    except SQLAlchemyError as e:
        session.rollback()
        log_error(f"Database error occurred while generating OTP for {email}: {str(e)}")
        return jsonify({"error": "Database error", "details": str(e)}), 500

    except Exception as e:
        session.rollback()
        log_error(f"Unexpected error occurred while generating OTP for {email}: {str(e)}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

    finally:
        session.close()
        log_info(f"End of generate_otp function for email={email}")


# ---------------------------------------------- RAILWAY USER TABLE ----------------------------------------------------

@app.route('/register', methods=['POST'])
@otp_required
def register_user():
    """
    Registers a new user with a username, password, and email.

    Sends an email notification upon success or failure.
    Provides voice notifications for both success and errors.

    Validates inputs:
    Username: At least 3 characters.
    Password: At least 6 characters.
    Email: Must be valid (contain '@').

    Checks if the username or email already exists.
    Hashes the password and stores the new user in the database.
    """
    log_info("Register user process started.")

    try:
        data = request.get_json()
        log_debug(f"Received registration data: {data}")

        username = data.get('username')
        password = data.get('password')
        useremail = data.get('useremail')

        if not username or not isinstance(username, str) or len(username) < 3:
            error_message = f"Invalid username: {username}. Must be at least 3 characters."
            log_warning(error_message)
            notify_failure("User Registration Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return {"message": error_message}, 400

        if not password or not isinstance(password, str) or len(password) < 6:
            error_message = f"Invalid password for user: {username}. Password must be at least 6 characters."
            log_warning(error_message)
            notify_failure("User Registration Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return {"message": error_message}, 400

        if not useremail or '@' not in useremail or len(useremail) < 5:
            error_message = f"Invalid email: {useremail}. Please provide a valid email address."
            log_warning(error_message)
            notify_failure("User Registration Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return {"message": error_message}, 400

        if session.query(Railway_User).filter_by(username=username).first():
            error_message = f"Username '{username}' already exists."
            log_warning(error_message)
            notify_failure("User Registration Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return {"message": error_message}, 409

        if session.query(Railway_User).filter_by(useremail=useremail).first():
            error_message = f"Email '{useremail}' already exists."
            log_warning(error_message)
            notify_failure("User Registration Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return {"message": error_message}, 409

        new_user = Railway_User(username=username, useremail=useremail)
        log_info(f"Creating new user: {username}")

        new_user.set_password(password)
        session.add(new_user)
        session.commit()

        user_id = new_user.user_id

        ist = pytz.timezone('Asia/Kolkata')
        creation_time = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S %Z")

        user_details = {
            "user_id": user_id,
            "username": username,
            "useremail": useremail,
            "creation_time_ist": creation_time
        }

        log_info(f"User registered successfully: {username} at {creation_time}")
        notify_success("User Registered Successfully",
                       f"User '{username}' (ID: {user_id}) has been successfully registered with useremail '{useremail}' at {creation_time} (IST).")

        send_email(
            [useremail],
            "Welcome to Railway Booking",
            f"Dear {username},\n\nYour registration was successful! Here are your details:\n"
            f"User ID: {user_id}\nUsername: {username}\nUserEmail: {useremail}\n"
            f"Registration Time (IST): {creation_time}\n\nThank you for registering!"
        )

        threading.Thread(target=speak, args=(f"User {username} has been successfully added.",)).start()

        return {
            "message": "User registered successfully.",
            "user_details": user_details
        }, 201

    except Exception as err:
        error_message = f"An error occurred during registration: {str(err)}"
        log_error(error_message)
        session.rollback()  # Rollback in case of any error
        notify_failure("User Registration Failed", error_message)
        threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
        return {"message": error_message}, 500
    finally:
        session.close()
        log_info("Register user process ended.")


@app.route('/users', methods=['GET'])
def get_users():
    """
    Fetches registered users' information.

    If username or email parameters are provided, it fetches the specific user.
    If no parameters are provided, it fetches all registered users.

    Returns user details in JSON format and voice notifications for failures.
    """

    log_info("Fetching registered users' information started.")

    try:
        username = request.args.get('username', '').strip()
        useremail = request.args.get('useremail', '').strip()

        query = session.query(Railway_User)

        if username:
            query = query.filter(Railway_User.username.ilike(f"%{username}%"))
        if useremail:
            query = query.filter(Railway_User.email.ilike(f"%{useremail}%"))

        users = query.all()

        log_debug(f"Number of registered users found: {len(users)}")

        if not users:
            message = "No registered users found for the given criteria."
            log_info(message)
            speak(message)
            return {"message": message}, 404

        user_details_list = []
        for user in users:
            user_details = {
                "user_id": user.user_id,
                "username": user.username,
                "useremail": user.useremail,
            }
            user_details_list.append(user_details)

        log_info("Fetched registered users' information successfully.")

        total_count = len(user_details_list)

        structured_message = "User Details:\n"
        for user in user_details_list:
            structured_message += (
                f"User ID: {user['user_id']}\n"
                f"Username: {user['username']}\n"
                f"UserEmail: {user['useremail']}\n"
                "--------------------\n"
            )

        structured_message += f"Total users retrieved: {total_count}\n"

        send_email_notification(structured_message)

        success_message = f"Details fetched successfully. Total users retrieved: {total_count}."
        speak(success_message)

        return {
            "message": "Registered users retrieved successfully.",
            "users": user_details_list,
            "total_count": total_count
        }, 200

    except Exception as err:
        error_message = f"An error occurred while fetching users: {str(err)}"
        log_error(error_message)
        speak(error_message)
        return {"message": error_message}, 500

    finally:
        session.close()
        log_info("Fetching registered users' information ended.")


@app.route('/update-users', methods=['PUT'])
@otp_required
def update_user():
    """
    Updates the information of a registered user, including their username, email, and password.

    Searches by user ID, username, or email.
    Requires OTP verification.
    :return: JSON response indicating success or failure.
    """

    log_info("Updating user information started.")

    try:
        data = request.get_json()

        if not data:
            message = "No data provided for update."
            log_info(message)
            speak(message)
            return {"message": message}, 400

        user_id = data.get('user_id')
        username = data.get('username')
        useremail = data.get('useremail')

        user = None
        if user_id:
            user = session.query(Railway_User).filter(Railway_User.user_id == user_id).first()
        elif username:
            user = session.query(Railway_User).filter(Railway_User.username == username).first()
        elif useremail:
            user = session.query(Railway_User).filter(Railway_User.useremail == useremail).first()

        if not user:
            message = "No user found with the provided identifier."
            log_info(message)
            speak(message)
            return {"message": message}, 404  # Not Found

        # Update user attributes based on the provided data
        if 'username' in data:
            user.username = data['username']
        if 'useremail' in data:
            user.useremail = data['useremail']
        if 'password' in data:
            user.set_password(data['password'])

        session.commit()
        log_info(f"User ID {user.user_id} updated successfully.")

        structured_message = (
            f"User Update Successful:\n"
            f"User ID: {user.user_id}\n"
            f"Updated Username: {user.username}\n"
            f"Updated UserEmail: {user.useremail}\n"
            f"Update Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        send_email_notification(structured_message)

        success_message = f"User ID {user.user_id} updated successfully."
        speak(success_message)

        return {
            "message": success_message,
            "user": {
                "user_id": user.user_id,
                "username": user.username,
                "useremail": user.useremail
            }
        }, 200

    except SQLAlchemyError as e:
        session.rollback()
        error_message = f"Database error occurred while updating user: {str(e)}"
        log_error(error_message)
        speak(error_message)
        return {"message": error_message}, 500

    except Exception as err:
        session.rollback()
        error_message = f"An error occurred while updating user: {str(err)}"
        log_error(error_message)
        speak(error_message)
        return {"message": error_message}, 500

    finally:
        session.close()
        log_info("Updating user information ended.")


@app.route('/delete-user', methods=['DELETE'])
@otp_required
def delete_user():
    """
    Deletes a registered user from the system by user ID, username, or email.
    Requires OTP verification.
    :return: JSON response indicating success or failure.
    """

    log_info("Deleting user started.")

    try:
        user_id = request.args.get('user_id')
        username = request.args.get('username')
        useremail = request.args.get('useremail')
        otp = request.args.get('otp')

        if not otp:
            message = "OTP is required for verification."
            log_error(message)
            speak(message)
            return {"message": message}, 400
        if not (user_id or username or useremail):
            message = "No user identifier provided (user_id, username, or email)."
            log_info(message)
            speak(message)
            return {"message": message}, 400

        user = None
        if user_id:
            user = session.query(Railway_User).filter(Railway_User.user_id == user_id).first()
        elif username:
            user = session.query(Railway_User).filter(Railway_User.username == username).first()
        elif useremail:
            user = session.query(Railway_User).filter(Railway_User.useremail == useremail).first()

        if not user:
            message = "No user found with the provided identifier."
            log_info(message)
            speak(message)
            return {"message": message}, 404

        # Delete the user
        session.delete(user)
        session.commit()
        log_info(f"User ID {user.user_id} deleted successfully.")

        structured_message = (
            f"User Deletion Successful:\n"
            f"User ID: {user.user_id}\n"
            f"Deleted Username: {user.username}\n"
            f"Deleted UserEmail: {user.useremail}\n"
            f"Deletion Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        send_email_notification(structured_message)

        success_message = f"User ID {user.user_id} deleted successfully."
        speak(success_message)

        return {
            "message": success_message,
            "user": {
                "user_id": user.user_id,
                "username": user.username,
                "useremail": user.useremail
            }
        }, 200

    except SQLAlchemyError as e:
        session.rollback()
        error_message = f"Database error occurred while deleting user: {str(e)}"
        log_error(error_message)
        speak(error_message)
        return {"message": error_message}, 500

    except Exception as err:
        session.rollback()
        error_message = f"An error occurred while deleting user: {str(err)}"
        log_error(error_message)
        speak(error_message)
        return {"message": error_message}, 500

    finally:
        session.close()
        log_info("Deleting user ended.")


# ---------------------------------------------- TRAIN TABLE -----------------------------------------------------------
# Train Creation API


if __name__ == "__main__":
    app.run(debug=True)

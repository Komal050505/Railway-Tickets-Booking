# Standard Library Imports
import time
from datetime import datetime
from random import random
from urllib import request
import threading

# Third-Party Library Imports
from flask import Flask, jsonify, request, session
import pytz
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
import requests
import psutil

# Project-Specific Imports
from App.email_configurations import RECEIVER_EMAIL, ADMIN_EMAIL
from App.email_operations import (
    notify_failure, send_email, notify_success, send_email_notification,
    send_email_otp, generate_train_email_body, fetch_train_email_body,
    construct_train_email_body, prepare_and_send_email,
    generate_route_email_body, generate_fetch_email_body, notify_deletion,
    handle_error, generate_booking_email_body, send_error_email,
    generate_booking_list_email_body, generate_update_booking_email_body
)
from Db_connections.configurations import session
from Logging_package.logging_utility import log_info, log_debug, log_warning, log_error
from Models.tables import Booking, Train, Railway_User, OTPStore, TrainRoute
from Utils.reusables import (
    speak, otp_required, generate_train_search_results,
    validate_time_format, validate_booking_data
)

app = Flask(__name__)


# ------------------------------------CHECKS OTHER APIS PERFORMANCES ---------------------------------------------------

@app.route('/check-api-performance', methods=['POST'])
def check_api_performance():
    """
    Check the performance of a specified API by sending a request and logging CPU and memory usage.

    :return: JSON response containing performance metrics or error message.
    """
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
        session.rollback()
        error_message = f"Failed to call the target API: {str(e)}"
        log_error(error_message)
        send_email(RECEIVER_EMAIL, "API Performance Check Failed", error_message)
        return jsonify({"error": error_message}), 500

    except Exception as e:
        session.rollback()
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
    Generates a One-Time Password (OTP) for the given email and sends it via email.
    The OTP is stored in the database for verification purposes.

    :return: JSON response indicating success or error.
    """
    email = None
    try:
        payload = request.get_json()
        if not payload or 'email' not in payload:
            log_error("Email is required to generate OTP.")
            return jsonify({"error": "Email is required to generate OTP."}), 400

        email = payload['email']
        otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
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
        session.rollback()
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
@app.route('/trains', methods=['POST'])
@otp_required
def add_train():
    """
    Add a new train record to the database.

    Sends an email notification upon success or failure.
    Provides voice notifications for both success and errors.
    """
    log_info("Starting the process of adding a new train.")

    try:
        data = request.get_json()
        log_debug(f"Received data for new train: {data}")

        # Extract fields from the received data
        train_name = data.get('train_name')
        train_number = data.get('train_number')
        source = data.get('source')
        destination = data.get('destination')
        departure_time = data.get('departure_time')
        arrival_time = data.get('arrival_time')
        available_seats = data.get('available_seats')
        total_seats = data.get('total_seats')

        # Validate the input fields
        missing_fields = []
        if not train_name:
            missing_fields.append("train_name")
        if not train_number:
            missing_fields.append("train_number")
        if not source:
            missing_fields.append("source")
        if not destination:
            missing_fields.append("destination")
        if not departure_time:
            missing_fields.append("departure_time")
        if not arrival_time:
            missing_fields.append("arrival_time")
        if available_seats is None:
            missing_fields.append("available_seats")
        if total_seats is None:
            missing_fields.append("total_seats")

        if missing_fields:
            error_message = f"Missing or invalid input data: {', '.join(missing_fields)}."
            log_error(error_message)
            notify_failure("Add Train Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return jsonify({"message": error_message}), 400

        # Check for duplicate train_number
        existing_train = session.query(Train).filter_by(train_number=train_number).first()
        if existing_train:
            error_message = f"Train with number '{train_number}' already exists."
            log_error(error_message)
            notify_failure("Add Train Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return jsonify({"message": error_message}), 400

        # Create a new train instance
        new_train = Train(
            train_name=train_name,
            train_number=train_number,
            source=source,
            destination=destination,
            departure_time=departure_time,
            arrival_time=arrival_time,
            available_seats=available_seats,
            total_seats=total_seats  # Assign total_seats
        )

        session.add(new_train)
        session.commit()

        ist = pytz.timezone('Asia/Kolkata')
        creation_time = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S %Z")

        log_info(f"Train '{train_name}' added successfully at {creation_time}.")

        # Notify success
        notify_success("Train Added Successfully",
                       f"Train '{train_name}' (Train Number: {train_number}) has been successfully added with the following details:\n"
                       f"Source: {source}\nDestination: {destination}\nDeparture Time: {departure_time}\n"
                       f"Arrival Time: {arrival_time}\nAvailable Seats: {available_seats}\n"
                       f"Total Seats: {total_seats}\nAdded at: {creation_time} (IST)")

        email_body = generate_train_email_body(train_name, train_number, source, destination, departure_time,
                                               arrival_time, available_seats, total_seats,
                                               creation_time)  # Include total_seats in email

        send_email(
            RECEIVER_EMAIL,
            "New Train Added",
            email_body
        )

        threading.Thread(target=speak, args=(f"Train {train_name} has been successfully added.",)).start()

        return jsonify({
            "message": "Train added successfully.",
            "train": new_train.to_dict(),
            "creation_time": creation_time
        }), 201

    except SQLAlchemyError as e:
        session.rollback()
        error_message = f"Error adding train: {str(e)}"
        log_error(error_message)
        notify_failure("Add Train Failed", error_message)
        threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
        return jsonify({"message": "Error adding train."}), 500

    except Exception as err:
        session.rollback()
        error_message = f"An unexpected error occurred: {str(err)}"
        log_error(error_message)
        notify_failure("Add Train Failed", error_message)
        threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
        return jsonify({"message": error_message}), 500

    finally:
        session.close()
        log_info("Finished the process of adding a new train.")


@app.route('/trains', methods=['GET'])
def fetch_trains():
    """
    Fetch train records based on search criteria.

    Supports case-insensitive search for train name, train number,
    source, destination, and other conditions.
    """
    log_info("Starting the process of fetching train records.")

    try:
        train_id = request.args.get('train_id')
        train_name = request.args.get('train_name')
        train_number = request.args.get('train_number')
        source = request.args.get('source')
        destination = request.args.get('destination')

        log_debug(
            f"Received search criteria: train_id={train_id}, train_name={train_name}, train_number={train_number}, source={source}, destination={destination}")

        query = session.query(Train)

        if train_id:

            try:
                train_id = int(train_id)
                query = query.filter(Train.train_id == train_id)
            except ValueError:
                log_error(f"Invalid train_id format: {train_id}")
                return jsonify({"message": "Invalid train_id format."}), 400
        if train_name:
            query = query.filter(Train.train_name.ilike(f'%{train_name}%'))
        if train_number:
            query = query.filter(Train.train_number.ilike(f'%{train_number}%'))
        if source:
            query = query.filter(Train.source.ilike(f'%{source}%'))
        if destination:
            query = query.filter(Train.destination.ilike(f'%{destination}%'))

        train_records = query.all()

        total_count = len(train_records)

        if total_count == 0:
            log_info("No train records found matching the criteria.")
            return jsonify({"message": "No train records found."}), 404

        results = generate_train_search_results(train_records)

        log_info(f"Found {total_count} train records matching the criteria.")

        email_body = fetch_train_email_body(results, total_count)
        send_email(
            RECEIVER_EMAIL,
            "Train Records Fetched",
            email_body
        )

        return jsonify(
            {"message": "Train records fetched successfully.", "trains": results, "total_count": total_count}), 200

    except SQLAlchemyError as e:
        session.rollback()
        error_message = f"Database error while fetching trains: {str(e)}"
        log_error(error_message)
        return jsonify({"message": "Error fetching train records."}), 500

    except Exception as err:
        session.rollback()
        error_message = f"An unexpected error occurred: {str(err)}"
        log_error(error_message)
        return jsonify({"message": error_message}), 500

    finally:
        session.close()
        log_info("Finished the process of fetching train records.")


@app.route('/trains', methods=['PUT'])
@otp_required
def update_train():
    """
    Update the details of an existing train record in the database.

    Sends an email notification upon success or failure.
    Provides voice notifications for both success and errors.
    """
    log_info("Starting the process of updating train.")

    try:
        data = request.get_json()
        log_debug(f"Received data for updating train: {data}")

        train_number = data.get('train_number')
        train_name = data.get('train_name')
        source = data.get('source')
        destination = data.get('destination')
        departure_time = data.get('departure_time')
        arrival_time = data.get('arrival_time')
        total_seats = data.get('total_seats')
        available_seats = data.get('available_seats')

        train_to_update = session.query(Train).filter(Train.train_number == train_number).first()

        if not train_to_update:
            error_message = f"Train with number '{train_number}' not found."
            log_error(error_message)
            notify_failure("Update Train Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return jsonify({"message": error_message}), 404

        error_messages = []

        if available_seats is not None:
            if not isinstance(available_seats, int) or available_seats < 0:
                error_messages.append("Available seats must be a non-negative integer.")

        if total_seats is not None:
            if not isinstance(total_seats, int) or total_seats <= 0:
                error_messages.append("Total seats must be a positive integer.")
            elif total_seats < available_seats:
                error_messages.append("Available seats cannot exceed total seats.")

        if departure_time and not validate_time_format(departure_time):
            error_messages.append("Invalid departure time format. Expected format is HH:MM.")

        if arrival_time and not validate_time_format(arrival_time):
            error_messages.append("Invalid arrival time format. Expected format is HH:MM.")

        if error_messages:
            error_message = "Validation failed: " + "; ".join(error_messages)
            log_error(error_message)
            notify_failure("Update Train Failed", error_message)
            threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
            return jsonify({"message": error_message}), 400

        if train_name:
            train_to_update.train_name = train_name
        if source:
            train_to_update.source = source
        if destination:
            train_to_update.destination = destination
        if departure_time:
            train_to_update.departure_time = departure_time
        if arrival_time:
            train_to_update.arrival_time = arrival_time
        if total_seats is not None:
            train_to_update.total_seats = total_seats
        if available_seats is not None:
            train_to_update.available_seats = available_seats

        session.commit()

        ist = pytz.timezone('Asia/Kolkata')
        update_time = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S %Z")

        log_info(f"Train '{train_number}' updated successfully at {update_time}.")

        notify_success("Train Updated Successfully",
                       f"Train '{train_number}' has been successfully updated with the following details:\n"
                       f"Name: {train_to_update.train_name}\nSource: {train_to_update.source}\n"
                       f"Destination: {train_to_update.destination}\nDeparture Time: {train_to_update.departure_time}\n"
                       f"Arrival Time: {train_to_update.arrival_time}\nTotal Seats: {train_to_update.total_seats}\n"
                       f"Available Seats: {train_to_update.available_seats}\n"
                       f"Updated at: {update_time} (IST)")

        email_body = construct_train_email_body(
            train_to_update.train_name,
            train_number,
            train_to_update.source,
            train_to_update.destination,
            train_to_update.departure_time,
            train_to_update.arrival_time,
            train_to_update.total_seats,
            train_to_update.available_seats,
            train_to_update.waiting_list_count,
            update_time
        )

        send_email(
            RECEIVER_EMAIL,
            "Train Updated",
            email_body
        )

        threading.Thread(target=speak, args=(f"Train {train_number} has been successfully updated.",)).start()

        return jsonify({
            "message": "Train updated successfully.",
            "train": train_to_update.to_dict(),
            "update_time": update_time
        }), 200

    except SQLAlchemyError as e:
        session.rollback()
        error_message = f"Error updating train: {str(e)}"
        log_error(error_message)
        notify_failure("Update Train Failed", error_message)
        threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
        return jsonify({"message": "Error updating train."}), 500

    except Exception as err:
        session.rollback()
        error_message = f"An unexpected error occurred: {str(err)}"
        log_error(error_message)
        notify_failure("Update Train Failed", error_message)
        threading.Thread(target=speak, args=(f"Error: {error_message}",)).start()
        return jsonify({"message": error_message}), 500

    finally:
        session.close()
        log_info("Finished the process of updating the train.")


@app.route('/trains', methods=['DELETE'])
@otp_required
def delete_trains():
    """Deletes a train based on the provided query parameters (train_id, train_name, or train_number)."""
    try:
        log_info(f"Received DELETE request with args: {request.args}")

        train_id = request.args.get('train_id')
        train_name = request.args.get('train_name')
        train_number = request.args.get('train_number')

        email = request.args.get('email')
        otp = request.args.get('otp')

        log_info(f"Email: {email}, OTP: {otp}")

        if not email or not otp:
            log_error("Email and OTP must be provided as query parameters.")
            return jsonify({"error": "Email and OTP must be provided."}), 400

        if not (train_id or train_name or train_number):
            log_error("At least one of 'train_id', 'train_name', or 'train_number' must be provided.")
            return jsonify(
                {"error": "At least one of 'train_id', 'train_name', or 'train_number' must be provided."}), 400

        # deleted_train_name = None

        train = None
        if train_id:
            train = session.query(Train).filter_by(train_id=int(train_id)).first()
        elif train_name:
            train = session.query(Train).filter_by(train_name=train_name).first()
        elif train_number:
            train = session.query(Train).filter_by(train_number=train_number).first()

        if train:
            deleted_train_name = train.train_name
            session.delete(train)
            log_info(f"Deleted train: {deleted_train_name}.")
        else:
            log_error("No train found to delete with provided parameters.")
            return jsonify({"error": "No train found to delete."}), 404

        session.commit()

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_info(f"Successfully deleted train: {deleted_train_name} at {current_time}")

        voice_message = f"Successfully deleted the train: {deleted_train_name} at {current_time}."

        threading.Thread(target=speak, args=(voice_message,)).start()

        prepare_and_send_email(action="deletion", train_details=[deleted_train_name], operation_time=current_time,
                               email=email)

        return jsonify(
            {"message": f"Successfully deleted train: {deleted_train_name}", "time_of_deletion": current_time}), 200

    except SQLAlchemyError as db_error:
        session.rollback()
        log_error(f"Database error during train deletion: {db_error}")
        return jsonify({"error": "Internal server error", "details": str(db_error)}), 500

    except Exception as e:
        session.rollback()
        log_error(f"Unexpected error during train deletion: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

    finally:
        session.close()
        log_info("Finished the process of Deleting Train")


# ---------------------------------------------- TRAIN ROUTE TABLE -----------------------------------------------------

@app.route('/add-train-route', methods=['POST'])
@otp_required
def add_train_route():
    """API to insert a new train route into the database."""

    email_body = None
    log_info("Initiating the process of adding a new train route")
    try:
        data = request.json
        log_info(f"Received data: {data}")

        train_number = data.get('train_number')
        train_name = data.get('train_name')
        station_name = data.get('station_name')
        arrival_time = data.get('arrival_time')
        departure_time = data.get('departure_time')
        origin_station = data.get('origin')
        destination_station = data.get('destination')

        if not all([train_number, train_name, station_name, arrival_time, departure_time, origin_station,
                    destination_station]):
            log_error(f"Missing required fields in request: {data}")
            return jsonify({"error": "Missing required fields"}), 400

        train = session.query(Train).filter_by(train_number=train_number).first()
        if not train:
            log_error(f"Train with number {train_number} not found in database")
            return jsonify({"error": f"Train with number {train_number} not found"}), 404

        existing_route = session.query(TrainRoute).filter_by(
            train_number=train_number,
            station_name=station_name
        ).first()

        if existing_route:
            log_error(f"Train route for {train_name} at {station_name} already exists")
            return jsonify({"error": "Train route already exists for this train number and station name"}), 409

        new_route = TrainRoute(
            train_number=train_number,
            train_name=train_name,
            station_name=station_name,
            arrival_time=arrival_time,
            departure_time=departure_time,
            origin=origin_station,
            destination=destination_station
        )

        session.add(new_route)
        session.commit()

        log_info(f"Successfully added train route for {train_name} at {station_name}")

        creation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        email_body = generate_route_email_body(
            train_name=train_name,
            train_number=train_number,
            station_name=station_name,
            arrival_time=arrival_time,
            departure_time=departure_time,
            creation_time=creation_time,
            origin=origin_station,
            destination=destination_station
        )

        send_email(
            to_email=ADMIN_EMAIL,
            subject="New Train Route Added",
            body=email_body
        )

        threading.Thread(target=speak, args=(f"Train {train_name} has been successfully added.",)).start()

        return jsonify({
            "message": "Train route added successfully",
            "route": {
                "train_number": train_number,
                "train_name": train_name,
                "station_name": station_name,
                "arrival_time": arrival_time,
                "departure_time": departure_time,
                "origin": origin_station,
                "destination": destination_station
            }
        }), 201

    except SQLAlchemyError as e:
        session.rollback()
        log_error(f"Database error: {str(e)}")

        if not email_body:
            email_body = f"Failed to add train route due to database error: {str(e)}"

        send_email(
            to_email=ADMIN_EMAIL,
            subject="Error Adding Train Route",
            body=email_body
        )
        threading.Thread(target=speak, args=("Error occurred while adding the train route.",)).start()
        return jsonify({"error": "Database error occurred"}), 500

    except Exception as e:
        session.rollback()
        log_error(f"Exception occurred: {str(e)}")

        if not email_body:
            email_body = f"Failed to add train route due to an unexpected error: {str(e)}"

        send_email(
            to_email=ADMIN_EMAIL,
            subject="Error Adding Train Route",
            body=email_body
        )
        threading.Thread(target=speak, args=("Unexpected error occurred while adding the train route.",)).start()
        return jsonify({"error": "An unexpected error occurred"}), 500

    finally:
        session.close()
        log_info("Finished the process of Adding New Train Route")


@app.route('/fetch-train-route', methods=['GET'])
def fetch_train_route():
    """API to fetch one or multiple train routes from the database with case-insensitive searches."""
    email_body = None
    log_info("Initiating the process of fetching train routes")
    try:
        train_number = request.args.get('train_number', '').strip().lower()
        station_name = request.args.get('station_name', '').strip().lower()
        origin = request.args.get('origin', '').strip().lower()
        destination = request.args.get('destination', '').strip().lower()
        route_id = request.args.get('route_id', None)

        filters = {}
        if train_number:
            filters['train_number'] = train_number
        if station_name:
            filters['station_name'] = station_name
        if origin:
            filters['origin'] = origin
        if destination:
            filters['destination'] = destination
        if route_id:
            filters['route_id'] = route_id

        query = session.query(TrainRoute)

        if route_id:
            query = query.filter(TrainRoute.route_id == route_id)
        else:
            if train_number:
                query = query.filter(TrainRoute.train_number.ilike(f'%{train_number}%'))
            if station_name:
                query = query.filter(TrainRoute.station_name.ilike(f'%{station_name}%'))
            if origin:
                query = query.filter(TrainRoute.origin.ilike(f'%{origin}%'))
            if destination:
                query = query.filter(TrainRoute.destination.ilike(f'%{destination}%'))

        train_routes = query.all()

        routes_data = [
            {
                "train_number": route.train_number,
                "train_name": route.train_name,
                "station_name": route.station_name,
                "arrival_time": str(route.arrival_time),
                "departure_time": str(route.departure_time),
                "origin": route.origin,
                "destination": route.destination,
                "route_id": route_id
            } for route in train_routes
        ]

        total_count = len(routes_data)

        if total_count == 0:
            log_error("No train routes found matching the provided filters")
            return jsonify({"message": "No train routes found", "total_count": total_count}), 404

        log_info(f"Successfully fetched {total_count} train route(s)")

        creation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        email_body = generate_fetch_email_body(
            routes=routes_data,
            creation_time=creation_time,
            total_count=total_count
        )

        send_email(
            to_email=ADMIN_EMAIL,
            subject="Train Routes Fetched",
            body=email_body
        )

        return jsonify({
            "message": "Train routes fetched successfully",
            "total_count": total_count,  # Include total count in the response
            "routes": routes_data
        }), 200

    except SQLAlchemyError as e:
        session.rollback()
        log_error(f"Database error: {str(e)}")

        if not email_body:
            email_body = f"Failed to fetch train routes due to database error: {str(e)}"

        send_email(
            to_email=ADMIN_EMAIL,
            subject="Error Fetching Train Routes",
            body=email_body
        )
        return jsonify({"error": "Database error occurred"}), 500

    except Exception as e:
        session.rollback()
        log_error(f"Exception occurred: {str(e)}")

        if not email_body:
            email_body = f"Failed to fetch train routes due to an unexpected error: {str(e)}"

        send_email(
            to_email=ADMIN_EMAIL,
            subject="Error Fetching Train Routes",
            body=email_body
        )
        return jsonify({"error": "An unexpected error occurred"}), 500

    finally:
        session.close()
        log_info("Finished the process of Fetching Train Routes")


@app.route('/update-train-route', methods=['PUT'])
@otp_required
def update_train_route():
    """API to update an existing train route in the database."""

    email_body = None
    route_id = None
    log_info("Initiating the process of updating the train route")

    try:
        data = request.json
        log_info(f"Received data: {data}")

        route_id = data.get('route_id')
        if not route_id:
            log_error("No route ID provided for update")
            return jsonify({"error": "Route ID is required"}), 400

        train_number = data.get('train_number')
        train_name = data.get('train_name')
        station_name = data.get('station_name')
        arrival_time = data.get('arrival_time')
        departure_time = data.get('departure_time')
        origin_station = data.get('origin')
        destination_station = data.get('destination')

        if not any([route_id, train_name, station_name, arrival_time, departure_time, origin_station,
                    destination_station]):
            log_error(f"No fields provided to update for route ID {route_id}")
            return jsonify({"error": "No fields provided to update"}), 400

        route_to_update = session.query(TrainRoute).filter_by(route_id=route_id).first()
        if not route_to_update:
            log_error(f"Train route with ID {route_id} not found in database")
            return jsonify({"error": f"Train route with ID {route_id} not found"}), 404

        if route_id:
            route_to_update.route_id = route_id
        if train_number:
            route_to_update.train_number = train_number
        if train_name:
            route_to_update.train_name = train_name
        if station_name:
            route_to_update.station_name = station_name
        if arrival_time:
            route_to_update.arrival_time = arrival_time
        if departure_time:
            route_to_update.departure_time = departure_time
        if origin_station:
            route_to_update.origin = origin_station
        if destination_station:
            route_to_update.destination = destination_station

        session.commit()

        log_info(f"Successfully updated train route ID {route_id}")

        creation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        email_body = generate_route_email_body(
            train_name=train_name or route_to_update.train_name,
            train_number=train_number or route_to_update.train_number,
            station_name=station_name or route_to_update.station_name,
            arrival_time=arrival_time or route_to_update.arrival_time,
            departure_time=departure_time or route_to_update.departure_time,
            creation_time=creation_time,
            origin=origin_station or route_to_update.origin,
            destination=destination_station or route_to_update.destination
        )

        send_email(
            to_email=ADMIN_EMAIL,
            subject="Train Route Updated",
            body=email_body
        )

        threading.Thread(target=speak, args=(f"Train route ID {route_id} has been successfully updated.",)).start()

        return jsonify({
            "message": "Train route updated successfully",
            "route": {
                "route_id": route_to_update.route_id,
                "train_number": route_to_update.train_number,
                "train_name": route_to_update.train_name,
                "station_name": route_to_update.station_name,
                "arrival_time": str(route_to_update.arrival_time),
                "departure_time": str(route_to_update.departure_time),
                "origin": route_to_update.origin,
                "destination": route_to_update.destination

            }
        }), 200

    except SQLAlchemyError as e:
        session.rollback()
        log_error(f"Database error while updating route ID {route_id}: {str(e)}")

        if not email_body:
            email_body = f"Failed to update train route ID {route_id} due to database error: {str(e)}"

        send_email(
            to_email=ADMIN_EMAIL,
            subject="Error Updating Train Route",
            body=email_body
        )
        threading.Thread(target=speak, args=("Error occurred while updating the train route.",)).start()
        return jsonify({"error": "Database error occurred"}), 500

    except Exception as e:
        session.rollback()
        log_error(f"Exception occurred while updating route ID {route_id}: {str(e)}")

        if not email_body:
            email_body = f"Failed to update train route ID {route_id} due to an unexpected error: {str(e)}"

        send_email(
            to_email=ADMIN_EMAIL,
            subject="Error Updating Train Route",
            body=email_body
        )
        threading.Thread(target=speak, args=("Unexpected error occurred while updating the train route.",)).start()
        return jsonify({"error": "An unexpected error occurred"}), 500

    finally:
        session.close()
        log_info("Finished the process of updating train route")


@app.route('/delete-train-route', methods=['DELETE'])
@otp_required
def delete_train_route():
    """API to delete a train route from the database based on any combination of query parameters."""

    log_info("Initiating the process of deleting a train route")

    email_time = datetime.now()
    deletion_time = datetime.now()
    formatted_deletion_time = None
    train_number = None
    station_name = None
    try:
        train_number = request.args.get('train_number')
        station_name = request.args.get('station_name')
        user_email = request.args.get('email')
        otp = request.args.get('otp')

        log_info(
            f"Received parameters: train_number={train_number}, station_name={station_name}, email={user_email}, otp={otp}")

        if not (train_number or station_name):
            log_error("Missing required query parameters: at least train_number or station_name must be provided")
            return jsonify({"error": "At least one of train_number or station_name is required"}), 400

        query = session.query(TrainRoute)

        if train_number:
            query = query.filter_by(train_number=train_number)
        if station_name:
            query = query.filter_by(station_name=station_name)

        route_to_delete = query.first()

        if not route_to_delete:
            log_error(f"Train route not found for train number: {train_number} and station name: {station_name}")
            return jsonify({"error": "Train route not found"}), 404

        formatted_deletion_time = deletion_time.strftime("%Y-%m-%d %H:%M:%S")

        session.delete(route_to_delete)
        session.commit()

        log_info(
            f"Successfully deleted train route for {route_to_delete.train_number} at {route_to_delete.station_name}")

        notify_deletion(route_to_delete.train_number, route_to_delete.station_name, deletion_status="success",
                        email_time=email_time, formatted_deletion_time=formatted_deletion_time)

        threading.Thread(target=speak,
                         args=(
                             f"Train route for {route_to_delete.train_number} at {route_to_delete.station_name} has been deleted.",)).start()

        return jsonify({
            "message": "Train route deleted successfully",
            "route": {
                "train_number": route_to_delete.train_number,
                "station_name": route_to_delete.station_name,
                "departure_time": route_to_delete.departure_time.strftime(
                    "%Y-%m-%d %H:%M:%S") if route_to_delete.departure_time else None,
                "arrival_time": route_to_delete.arrival_time.strftime(
                    "%Y-%m-%d %H:%M:%S") if route_to_delete.arrival_time else None,
                "deleted_at": formatted_deletion_time,

            }
        }), 200

    except SQLAlchemyError as e:
        session.rollback()
        log_error(f"Database error: {str(e)}")

        notify_deletion(train_number, station_name, deletion_status="error", email_time=email_time,
                        formatted_deletion_time=formatted_deletion_time)

        threading.Thread(target=speak, args=("Error occurred while deleting the train route.",)).start()
        return jsonify({"error": "Database error occurred"}), 500

    except Exception as e:
        session.rollback()
        log_error(f"Exception occurred: {str(e)}")

        notify_deletion(train_number, station_name, deletion_status="error", email_time=email_time,
                        formatted_deletion_time=formatted_deletion_time)

        threading.Thread(target=speak, args=("Unexpected error occurred while deleting the train route.",)).start()
        return jsonify({"error": "An unexpected error occurred"}), 500

    finally:
        session.close()
        log_info("Finished the process of Deleting Train Route")


# ---------------------------------------------- BOOKING TABLE -----------------------------------------------------


@app.route('/book-ticket', methods=['POST'])
@otp_required
def book_ticket():
    """
    Handle the booking of train tickets by users.

    This endpoint accepts a POST request with JSON data containing user booking details.
    It validates the input, creates a new booking record in the database, and returns
    the booking confirmation. In case of errors, it handles exceptions, logs the errors,
    sends email notifications, and rolls back any database changes.

    Request Payload (JSON):
        user_id (str): The ID of the user booking the ticket.
        train_id (str): The ID of the train to be booked.
        seats_booked (int): The number of seats to be booked.
        seat_preference (str, optional): The user's seat preference, default is "No preference".
        travel_date (str): The travel date in 'YYYY-MM-DD' format.
        source (str): The source station of the journey.
        destination (str): The destination station of the journey.

    """
    log_info("Received request to /book-ticket endpoint.")
    try:
        data = request.get_json()
        if not data:
            raise ValueError("Request payload is missing")

        log_debug(f"Received data: {data}")

        is_valid, error_message = validate_booking_data(data)
        if not is_valid:
            raise ValueError(error_message)

        user_id = data['user_id']
        traveler_name = data['traveler_name']
        train_id = data['train_id']
        train_number = data['train_number']
        train_name = data['train_name']
        seats_booked = data['seats_booked']
        seat_preference = data.get('seat_preference', "No preference")
        travel_date = datetime.strptime(data['travel_date'], '%Y-%m-%d').date()
        source = data['source']
        destination = data['destination']
        booking_date = datetime.now()

        log_info(f"Creating booking for user {user_id} ({traveler_name}) on train {train_id}.")

        new_booking = Booking(
            user_id=user_id,
            traveler_name=traveler_name,
            train_id=train_id,
            train_number=train_number,
            train_name=train_name,
            seats_booked=seats_booked,
            seat_preference=seat_preference,
            travel_date=travel_date,
            booking_date=booking_date,
            source=source,
            destination=destination
        )

        session.add(new_booking)
        session.commit()

        log_info(f"Booking {new_booking.booking_id} created successfully.")

        generate_booking_email_body(
            booking_id=new_booking.booking_id,
            username=traveler_name,
            train_number=train_number,
            train_name=train_name,
            seats_booked=seats_booked,
            seat_preference=seat_preference,
            booking_date=booking_date.strftime('%Y-%m-%d'),
            travel_date=travel_date.strftime('%Y-%m-%d'),
            source=source,
            destination=destination,
            creation_time=booking_date.strftime('%Y-%m-%d %H:%M:%S'),

        )
        threading.Thread(target=speak,
                         args=(f"Booking {new_booking.booking_id} successfully created for user {user_id}.",)).start()

        return jsonify({"success": "Booking created successfully", "booking": new_booking.to_dict()}), 201

    except SQLAlchemyError as e:
        session.rollback()
        error_message = f"Database error occurred while booking: {str(e)}"
        handle_error(e, "Error Adding Booking", error_message)

        threading.Thread(target=speak, args=("A database error occurred while creating the booking.",)).start()

        return jsonify({"error": "Database error occurred"}), 500

    except Exception as e:
        session.rollback()
        error_message = f"Unexpected error occurred while booking: {str(e)}"
        handle_error(e, "Unexpected Error Creating Booking", error_message)

        threading.Thread(target=speak, args=("An unexpected error occurred while creating the booking.",)).start()

        return jsonify({"error": "An unexpected error occurred"}), 500

    finally:
        session.close()
        log_info("Finished the process of creating booking.")


@app.route('/get-bookings', methods=['GET'])
def get_bookings():
    """
    Fetch booking details with optional search filters and pagination.

    This endpoint allows you to search for bookings based on various filters such as user_id, traveler_name,
    train_name, travel_date, source, and destination. It also supports pagination using the 'limit' and 'offset'
    query parameters. Results are case-insensitive.
    :return: Returns a JSON response containing booking details, the total number of results, and pagination info.

    """
    log_info("Received request to /get-bookings endpoint.")
    try:
        user_id = request.args.get('user_id')
        traveler_name = request.args.get('traveler_name')
        train_id = request.args.get('train_id')
        train_name = request.args.get('train_name')
        seats_booked = request.args.get('seats_booked')
        seat_preference = request.args.get('seat_preference')
        booking_date = request.args.get('booking_date')
        travel_date = request.args.get('travel_date')
        source = request.args.get('source')
        destination = request.args.get('destination')
        limit = int(request.args.get('limit', 10))  # Default limit for pagination
        offset = int(request.args.get('offset', 0))  # Default offset for pagination

        query = session.query(Booking)

        if user_id:
            query = query.filter(Booking.user_id == user_id)
        if traveler_name:
            query = query.filter(Booking.traveler_name.ilike(f'%{traveler_name}%'))
        if train_id:
            query = query.filter(Booking.train_id == train_id)
        if train_name:
            query = query.filter(Booking.train_name.ilike(f'%{train_name}%'))
        if seats_booked:
            query = query.filter(Booking.seats_booked == seats_booked)
        if seat_preference:
            query = query.filter(Booking.seat_preference.ilike(f'%{seat_preference}%'))
        if booking_date:
            query = query.filter(func.date(Booking.booking_date) == booking_date)
        if travel_date:
            query = query.filter(func.date(Booking.travel_date) == travel_date)
        if source:
            query = query.filter(Booking.source.ilike(f'%{source}%'))
        if destination:
            query = query.filter(Booking.destination.ilike(f'%{destination}%'))

        total_count = query.count()
        log_info(f"Total booking count: {total_count}")

        bookings = query.offset(offset).limit(limit).all()

        booking_list = [booking.to_dict() for booking in bookings]
        log_info(f"Fetched {len(booking_list)} bookings successfully")
        email_body = generate_booking_list_email_body(booking_list, total_count)

        subject = "Bookings Fetch Success"
        send_email(ADMIN_EMAIL, subject, email_body)

        threading.Thread(target=speak, args=(f"{len(booking_list)} bookings fetched successfully.",)).start()

        return jsonify({
            'total_count': total_count,
            'limit': limit,
            'offset': offset,
            'bookings': booking_list
        }), 200

    except Exception as e:
        log_error(f"Error occurred while fetching bookings: {str(e)}")
        send_error_email("Bookings Fetch Failure", str(e))

        threading.Thread(target=speak, args=("Failed to fetch bookings.",)).start()

        return jsonify({'error': 'Error fetching bookings', 'message': str(e)}), 500


@app.route('/update-bookings', methods=['PUT'])
@otp_required
def update_bookings():
    """
    Update booking details for a specific booking ID provided in the JSON body.
    """
    log_info("Received request to update booking.")
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        booking_id = data.get('booking_id')
        if not booking_id:
            return jsonify({'error': 'Booking ID not provided'}), 400

        booking = session.query(Booking).filter(Booking.booking_id == booking_id).first()
        if not booking:
            return jsonify({'error': 'Booking not found'}), 404

        username = booking.traveler_name
        train_number = booking.train_id
        train_name = booking.train_name
        seats_booked = booking.seats_booked
        seat_preference = booking.seat_preference
        booking_date = booking.booking_date
        travel_date = booking.travel_date
        source = booking.source
        destination = booking.destination

        if 'traveler_name' in data:
            booking.traveler_name = data['traveler_name']
        if 'seats_booked' in data:
            booking.seats_booked = data['seats_booked']
        if 'seat_preference' in data:
            booking.seat_preference = data['seat_preference']
        if 'booking_date' in data:
            booking.booking_date = data['booking_date']
        if 'travel_date' in data:
            booking.travel_date = data['travel_date']
        if 'source' in data:
            booking.source = data['source']
        if 'destination' in data:
            booking.destination = data['destination']

        utc_time = datetime.utcnow()
        ist_timezone = pytz.timezone('Asia/Kolkata')
        updated_time = utc_time.replace(tzinfo=pytz.utc).astimezone(ist_timezone)
        booking.updated_time = updated_time
        formatted_updated_time = updated_time.strftime('%Y-%m-%d %I:%M:%S %p')
        session.commit()

        updated_booking = booking.to_dict()
        log_info(f"Booking with ID {booking_id} updated successfully.")

        generate_update_booking_email_body(booking_id, username, train_number, train_name, seats_booked,
                                           seat_preference, booking_date, travel_date, source, destination,
                                           formatted_updated_time)

        threading.Thread(target=speak, args=(f"Booking ID {booking_id} updated successfully.",)).start()

        return jsonify({'message': 'Booking updated successfully',
                        'booking': updated_booking,
                        'updated_time': formatted_updated_time}), 200

    except Exception as e:
        log_error(f"Error occurred while updating booking: {str(e)}")
        send_error_email("Booking Update Failure", str(e))

        threading.Thread(target=speak, args=("Failed to update booking.",)).start()

        return jsonify({'error': 'Error updating booking', 'message': str(e)}), 500


if __name__ == "__main__":
    log_info(f"Starting the Flask application {app}.")
    app.run(debug=True)
    log_info("Flask application has stopped.")

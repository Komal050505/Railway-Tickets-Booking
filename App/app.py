import time
from random import random
from urllib import request

from flask import Flask, jsonify, request, session
from datetime import datetime
import pytz

from sqlalchemy.exc import SQLAlchemyError

from App.email_configurations import RECEIVER_EMAIL
from App.email_operations import notify_failure, send_email, notify_success, send_email_notification, send_email_otp, \
    generate_train_email_body, fetch_train_email_body, construct_train_email_body, prepare_and_send_email
from Db_connections.configurations import session
from Logging_package.logging_utility import log_info, log_debug, log_warning, log_error
from Models.tables import Booking, Train, Railway_User, OTPStore
import pyttsx3
import threading
from Utils.reusables import speak, otp_required, generate_train_search_results, validate_time_format
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
@otp_required  # Keep the existing OTP validation
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
            return jsonify({"error": "At least one of 'train_id', 'train_name', or 'train_number' must be provided."}), 400

        deleted_train_name = None

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

# ---------------------------------------------- TRAIN TABLE -----------------------------------------------------------
'''
@app.route('/bookings', methods=['POST'])
@otp_required  # Apply the OTP decorator to the endpoint
def create_booking():
    """Create a new booking."""

    try:
        data = request.get_json()

        # Log the incoming request data
        log_info(f"Received data for booking: {data}")

        # Validate input data
        validation_error = validate_booking_data(data)
        if validation_error:
            log_error(f"Validation Error: {validation_error}")
            return jsonify({"error": validation_error}), 400

        # Record the time of booking
        booking_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Create a new booking instance
        new_booking = Booking(
            user_id=data['user_id'],
            train_id=data['train_id'],
            seats_booked=data['seats_booked']
        )

        # Add and commit the new booking to the database
        session.add(new_booking)
        session.commit()

        # Log the successful booking creation
        log_info(f"Created booking: {new_booking.booking_id} at {booking_time}")

        # Send the email notification using the new function
        send_booking_confirmation_email(
            recipient=data['email'],
            booking_id=new_booking.booking_id,
            user_id=new_booking.user_id,
            train_id=new_booking.train_id,
            seats_booked=new_booking.seats_booked,
            booking_time=booking_time
        )

        # Return the booking details as JSON
        return jsonify(new_booking.to_dict()), 201

    except SQLAlchemyError as db_error:
        session.rollback()
        log_error(f"Database error during booking creation: {db_error}")
        return jsonify({"error": "Database error", "details": str(db_error)}), 500

    except Exception as e:
        log_error(f"Unexpected error during booking creation: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

    finally:
        session.close()  # Ensure the session is closed regardless of success or failure
'''

if __name__ == "__main__":
    app.run(debug=True)

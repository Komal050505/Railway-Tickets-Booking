# SQLAlchemy Imports
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Date, Time, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash

from App.constants import SEAT_PREFERENCE

Base = declarative_base()


# ---------------------------------------------- OTP STORE TABLE -------------------------------------------------------

class OTPStore(Base):
    __tablename__ = 'otp_store'

    """
    Represents a one-time password (OTP) storage in the system.

    Attributes:
        id (int): Unique identifier for the OTP entry.
        email (str): The email address associated with the OTP.
        otp (str): The one-time password generated for the user.
        timestamp (datetime): The time when the OTP was generated.

    Methods:
        to_dict(): Converts the OTPStore object to a dictionary for JSON response.
    """

    id = Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False)
    otp = Column(String(6), nullable=False)
    timestamp = Column(DateTime, nullable=False)

    def __init__(self, email, otp, timestamp):
        """Initialize an OTPStore object with email, otp, and timestamp."""
        self.email = email
        self.otp = otp
        self.timestamp = timestamp

    def to_dict(self):
        """Convert OTPStore object to dictionary for JSON response."""
        return {
            "id": self.id,
            "email": self.email,
            "otp": self.otp,
            "timestamp": self.timestamp.isoformat()  # Format timestamp as ISO string
        }


# ---------------------------------------------- RAILWAY USER TABLE ----------------------------------------------------

# Database models
class Railway_User(Base):
    __tablename__ = 'railway_user'

    """
        Represents a user in the railway booking system.

        Attributes:
            user_id (int): Unique identifier for the user.
            username (str): Unique username for the user.
            password (str): Password for the user's account, stored as a hashed value.
            useremail (str): Unique email address associated with the user.
            creation_time (datetime): The time when the user account was created.

        Methods:
            set_password(password): Hashes and sets the user's password.
            check_password(password): Checks if the provided password matches the stored hashed password.
            to_dict(): Converts the user object to a dictionary for JSON response.
        """

    user_id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(512), nullable=False)
    useremail = Column(String(120), unique=True, nullable=False)
    creation_time = Column(DateTime, default=func.now())

    def set_password(self, password):
        """Set password for user."""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password is correct."""
        return check_password_hash(self.password, password)

    def to_dict(self):
        """Convert user object to dictionary for JSON response."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "useremail": self.useremail
        }

    bookings = relationship("Booking", back_populates="user")


# ---------------------------------------------- TRAIN TABLE -----------------------------------------------------------

class Train(Base):
    __tablename__ = 'train'

    """
    Represents a train in the railway booking system.

    Attributes:
        train_id (int): Unique identifier for the train.
        train_name (str): Name of the train.
        train_number (str): Unique train number.
        source (str): Departure station of the train.
        destination (str): Arrival station of the train.
        departure_time (str): Scheduled departure time.
        arrival_time (str): Scheduled arrival time.
        total_seats (int): Total number of seats available on the train.
        available_seats (int): Number of seats currently available for booking.
        waiting_list_count (int): Count of passengers on the waiting list.

    Methods:
        is_seat_available(seats_requested): Checks if the requested number of seats is available.
        update_seat_availability(seats_booked): Updates the available seats after booking.
        add_to_waiting_list(): Increments waiting list count.
        to_dict(): Converts the train object to a dictionary for JSON response.
    """

    train_id = Column(Integer, primary_key=True)
    train_name = Column(String(120), nullable=False)
    train_number = Column(String(20), nullable=False, unique=True)
    source = Column(String(120), nullable=False)
    destination = Column(String(120), nullable=False)
    departure_time = Column(String(50), nullable=False)
    arrival_time = Column(String(50), nullable=False)
    total_seats = Column(Integer, nullable=False)
    available_seats = Column(Integer, nullable=False)
    waiting_list_count = Column(Integer, default=0)

    def is_seat_available(self, seats_requested):
        """Check if the requested number of seats is available."""
        return self.available_seats >= seats_requested

    def update_seat_availability(self, seats_booked):
        """Update the available seats after booking."""
        if self.is_seat_available(seats_booked):
            self.available_seats -= seats_booked
            return True
        return False

    def add_to_waiting_list(self):
        """Increment waiting list count."""
        self.waiting_list_count += 1

    def to_dict(self):
        """Convert train object to dictionary for JSON response."""
        return {
            "train_id": self.train_id,
            "train_name": self.train_name,
            "train_number": self.train_number,
            "source": self.source,
            "destination": self.destination,
            "departure_time": self.departure_time,
            "arrival_time": self.arrival_time,
            "total_seats": self.total_seats,
            "available_seats": self.available_seats,
            "waiting_list_count": self.waiting_list_count
        }

        # Establish relationships

    bookings = relationship("Booking", back_populates="train")
    routes = relationship("TrainRoute", order_by="TrainRoute.route_id", back_populates="train")


# ---------------------------------------------- TRAIN ROUTE TABLE -----------------------------------------------------

class TrainRoute(Base):
    __tablename__ = 'train_routes'

    """
       Represents a train route in the railway booking system.

       Attributes:
           route_id (int): Unique identifier for the train route.
           train_number (str): Foreign key referencing the train number associated with this route.
           train_name (str): Name of the train for this route.
           station_name (str): Name of the station for this route.
           arrival_time (time): Scheduled arrival time at the station.
           departure_time (time): Scheduled departure time from the station.
           origin (str): Origin station of the train route.
           destination (str): Destination station of the train route.
       """

    route_id = Column(Integer, primary_key=True, autoincrement=True)
    train_number = Column(String(50), ForeignKey('train.train_number'),
                          nullable=False)  # Foreign key reference to train number
    train_name = Column(String(100), nullable=False)
    station_name = Column(String(100), nullable=False)
    arrival_time = Column(Time, nullable=False)
    departure_time = Column(Time, nullable=False)
    origin = Column(String(255), nullable=False)
    destination = Column(String(255), nullable=False)

    # Define a relationship to the Train table if needed
    train = relationship("Train", back_populates="routes")

    def to_dict(self):
        """Convert TrainRoute object to dictionary for JSON response."""
        return {
            "route_id": self.route_id,
            "train_number": self.train_number,
            "train_name": self.train_name,
            "station_name": self.station_name,
            "arrival_time": str(self.arrival_time),
            "departure_time": str(self.departure_time),
            "origin": self.origin,
            "destination": self.destination
        }


# Relationship back_populates for Train
Train.routes = relationship("TrainRoute", order_by=TrainRoute.route_id, back_populates="train")


# ---------------------------------------------- BOOKING TABLE ---------------------------------------------------------

class Booking(Base):
    __tablename__ = 'booking'

    """
    Represents a booking in the railway booking system.

    Attributes:
        booking_id (int): Unique identifier for the booking.
        user_id (int): Foreign key referencing the user who made the booking.
        traveler_name (str): Name of the traveler (can be the same as user).
        train_id (int): Foreign key referencing the train associated with this booking.
        train_name (str): Name of the train associated with this booking.
        train_number (str): Unique train number associated with this booking.
        seats_booked (int): Number of seats booked.
        seat_preference (str): Preferred seating arrangement (if any).
        booking_date (date): Date when the booking was created.
        travel_date (date): Scheduled date for travel.
        source (str): Departure station.
        destination (str): Arrival station.
    """

    booking_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('railway_user.user_id'), nullable=False)
    traveler_name = Column(String, nullable=False)
    train_id = Column(Integer, ForeignKey('train.train_id'), nullable=False)
    train_name = Column(String, nullable=False)  # Just as a normal attribute
    train_number = Column(String, nullable=False)
    seats_booked = Column(Integer, nullable=False)
    seat_preference = Column(String, nullable=True)  # Assuming SEAT_PREFERENCE is defined elsewhere
    booking_date = Column(Date, nullable=False)
    travel_date = Column(Date, nullable=False)
    source = Column(String(100), nullable=False)
    destination = Column(String(100), nullable=False)

    # Establish relationships
    user = relationship("Railway_User", back_populates="bookings")
    train = relationship("Train", back_populates="bookings")
    passengers = relationship("Passenger", back_populates="booking")


    def to_dict(self):
        """Convert booking object to dictionary for JSON response."""
        return {
            "booking_id": self.booking_id,
            "user_id": self.user_id,
            "username": self.user.username,  # Get username from Railway_User
            "traveler_name": self.traveler_name,
            "train_id": self.train_id,
            "train_name": self.train.train_name,
            "train_number": self.train_number,  # Include train_number in the response
            "seats_booked": self.seats_booked,
            "seat_preference": self.seat_preference,
            "booking_date": self.booking_date.isoformat(),
            "travel_date": self.travel_date.isoformat(),
            "source": self.source,
            "destination": self.destination
        }


# -------------------------------------------- PASSENGER TABLE ---------------------------------------------------------
class Passenger(Base):
    __tablename__ = 'passenger'
    """
    Represents a passenger in the railway booking system.

    Attributes:
        passenger_id (int): Unique identifier for the passenger.
        booking_id (int): Foreign key referencing the booking this passenger is associated with.
        name (str): Name of the passenger.
        gender (str): Gender of the passenger (M/F/Others).
        age (int): Age of the passenger.
        is_minor (bool): Indicates if the passenger is a minor (True if age < 18).
        is_physically_challenged (bool): Indicates if the passenger is physically challenged (True/False).
        is_military (bool): Indicates if the passenger is currently or previously in the military (True/False).
        aadhar_number (str): Aadhar number of the passenger (optional).
    """
    passenger_id = Column(Integer, primary_key=True)
    booking_id = Column(Integer, ForeignKey('booking.booking_id'), nullable=False)
    name = Column(String, nullable=False)
    gender = Column(String(10), nullable=False)  # M/F/Others
    age = Column(Integer, nullable=False)
    is_minor = Column(Boolean, default=False)  # True if age < 18, False otherwise
    is_physically_challenged = Column(Boolean, default=False)  # True/False for physically challenged status
    is_military = Column(Boolean, default=False)  # True/False for current/ex military status

    # Aadhar number field
    aadhar_number = Column(String(12), nullable=True)

    # Establish relationships
    booking = relationship("Booking", back_populates="passengers")

    def to_dict(self):
        """
        Convert passenger object to dictionary for JSON response.
        :return:
        """
        return {
            "passenger_id": self.passenger_id,
            "name": self.name,
            "gender": self.gender,
            "age": self.age,
            "is_minor": self.is_minor,
            "is_physically_challenged": self.is_physically_challenged,
            "is_military": self.is_military,
            "aadhar_number": self.aadhar_number,
        }

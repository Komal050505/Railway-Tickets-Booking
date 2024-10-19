# SQLAlchemy Imports
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Date, Time
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash

from App.constants import SEAT_PREFERENCE

Base = declarative_base()


# ---------------------------------------------- OTP STORE TABLE ----------------------------------------------------

class OTPStore(Base):
    __tablename__ = 'otp_store'

    id = Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False)
    otp = Column(String(6), nullable=False)
    timestamp = Column(DateTime, nullable=False)

    def __init__(self, email, otp, timestamp):
        self.email = email
        self.otp = otp
        self.timestamp = timestamp


# ---------------------------------------------- RAILWAY USER TABLE ----------------------------------------------------

# Database models
class Railway_User(Base):
    __tablename__ = 'railway_user'
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


# ---------------------------------------------- TRAIN TABLE -----------------------------------------------------------

class Train(Base):
    __tablename__ = 'train'
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


class TrainRoute(Base):
    __tablename__ = 'train_routes'

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


class Booking(Base):
    __tablename__ = 'booking'
    booking_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('railway_user.user_id'), nullable=False)
    train_id = Column(Integer, ForeignKey('train.train_id'), nullable=False)
    seats_booked = Column(Integer, nullable=False)
    seat_preference = Column(SEAT_PREFERENCE, nullable=True)
    booking_date = Column(Date, nullable=False)
    travel_date = Column(Date, nullable=False)
    status = Column(String(50), default='Confirmed')
    source = Column(String(100), nullable=False)
    destination = Column(String(100), nullable=False)

    # Establish relationships
    user = relationship("Railway_User", back_populates="bookings")
    train = relationship("Train", back_populates="bookings")

    def to_dict(self):
        """Convert booking object to dictionary for JSON response."""
        return {
            "booking_id": self.booking_id,
            "user_id": self.user_id,
            "username": self.user.username,  # Get username from Railway_User
            "train_id": self.train_id,
            "train_name": self.train.train_name,
            "seats_booked": self.seats_booked,
            "seat_preference": self.seat_preference,
            "booking_date": self.booking_date,
            "travel_date": self.travel_date,
            "status": self.status,
            "source": self.source,
            "destination": self.destination
        }


# Relationship back_populates for user and train
Railway_User.bookings = relationship("Booking", order_by=Booking.booking_id, back_populates="user")
Train.bookings = relationship("Booking", order_by=Booking.booking_id, back_populates="train")

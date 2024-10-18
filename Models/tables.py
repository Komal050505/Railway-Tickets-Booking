# SQLAlchemy Imports
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash

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
    source = Column(String(120), nullable=False)
    destination = Column(String(120), nullable=False)
    departure_time = Column(String(50), nullable=False)
    arrival_time = Column(String(50), nullable=False)
    available_seats = Column(Integer, nullable=False)

    def is_seat_available(self, seats_requested):
        """Check if the requested number of seats is available."""
        return self.available_seats >= seats_requested

    def update_seat_availability(self, seats_booked):
        """Update the available seats after booking."""
        if self.is_seat_available(seats_booked):
            self.available_seats -= seats_booked
            return True
        return False

    def to_dict(self):
        """Convert train object to dictionary for JSON response."""
        return {
            "train_id": self.train_id,
            "train_name": self.train_name,
            "source": self.source,
            "destination": self.destination,
            "departure_time": self.departure_time,
            "arrival_time": self.arrival_time,
            "available_seats": self.available_seats
        }


# ---------------------------------------------- BOOKING TABLE ---------------------------------------------------------

class Booking(Base):
    __tablename__ = 'booking'
    booking_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.user_id'), nullable=False)
    train_id = Column(Integer, ForeignKey('train.train_id'), nullable=False)
    seats_booked = Column(Integer, nullable=False)

    def to_dict(self):
        """Convert booking object to dictionary for JSON response."""
        return {
            "booking_id": self.booking_id,
            "user_id": self.user_id,
            "train_id": self.train_id,
            "seats_booked": self.seats_booked
        }

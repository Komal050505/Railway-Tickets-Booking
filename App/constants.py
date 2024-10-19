from sqlalchemy import Enum

VOICE_NOTIFICATIONS_ENABLED = False  # Default is on
SEAT_PREFERENCE = Enum('Window', 'Aisle', 'Upper', 'Lower', name='seat_preference')
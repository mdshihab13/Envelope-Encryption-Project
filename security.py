import re
import bleach
import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger(__name__)

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

ALLOWED_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{3,32}$')
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def hash_password(plaintext: str) -> str:
    return ph.hash(plaintext)


def verify_password(stored_hash: str, plaintext: str) -> bool:
    try:
        return ph.verify(stored_hash, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return ph.check_needs_rehash(stored_hash)


def sanitize_input(value: str) -> str:
    """Strip all HTML tags and dangerous content."""
    return bleach.clean(str(value), tags=[], strip=True).strip()


def validate_username(username: str) -> tuple[bool, str]:
    username = sanitize_input(username)
    if not username:
        return False, "Username required."
    if not ALLOWED_USERNAME_RE.match(username):
        return False, "Username: 3–32 chars, letters/numbers/_ only."
    return True, username


def validate_email(email: str) -> tuple[bool, str]:
    email = sanitize_input(email).lower()
    if not email:
        return False, "Email required."
    if not EMAIL_RE.match(email):
        return False, "Invalid email format."
    if len(email) > 254:
        return False, "Email too long."
    return True, email


def validate_password(password: str) -> tuple[bool, str]:
    if not password:
        return False, "Password required."
    if len(password) < 8:
        return False, "Password min 8 characters."
    if len(password) > 128:
        return False, "Password max 128 characters."
    if not re.search(r'[A-Z]', password):
        return False, "Password needs uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password needs lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password needs digit."
    return True, "OK"


def validate_login_identifier(identifier: str) -> tuple[bool, str]:
    identifier = sanitize_input(identifier)
    if not identifier:
        return False, "Username or email required."
    if len(identifier) > 254:
        return False, "Input too long."
    return True, identifier

#!/usr/bin/env python3
"""module for authentication
"""

import bcrypt
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User

logging.disable(logging.WARNING)

def _hash_password(self, password: str) ->bytes:
    """ Hashes a password that return bytes.

    Args:
    password(str): the password to be hashed

    Return:
    bytes: the hashed password
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

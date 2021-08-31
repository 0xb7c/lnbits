import datetime

import hashlib
import jwt

from lnbits.settings import SECRET_KEY
from lnbits.core.crud import get_user


def get_jwt_for_user(user):
    expiration_date = datetime.datetime.now() + datetime.timedelta(days=1)
    encoded = jwt.encode({
        "id": user.id,
        "exp": datetime.datetime.strftime(expiration_date, "%s"),
    }, SECRET_KEY, algorithm="HS256")

    return encoded


def validate_jwt_token(token):
    now = datetime.datetime.now()
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms="HS256")
        if int(decoded_token["exp"]) < int(datetime.datetime.strftime(now, "%s")):
            return False, None
        user = get_user(decoded_token["id"])
        if not user:
            return False, None
        return True, user
    except:
        return False, None


def get_hashed_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt + key


def validate_hashed_password(hashed_password, password):
    salt = hashed_password[:32]
    key = hashed_password[32:]

    provided_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )

    return provided_key == key

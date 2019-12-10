import pytest
import re
from db import get_db
from flask import g, session


def test_register(client, app):
	#test that a user is registered properly
    assert client.get('/register').status_code == 200
    response = client.post(
        '/register', data={'uname': 'user', 'pword': 'p','2fa': '123456789'}
    )

    with app.app_context():
        assert get_db().execute(
            "select * from user where username = 'user'",
        ).fetchone() is not None

def test_login_valid_input(auth, username, password, twofactor, message):
    response = auth.login(username, password, twofactor)
    assert message in response.data
    assert b"id=\"result\"" in response.data
import pytest
import requests, unittest
from flask import g, session
from db import get_db


class TestCases(unittest.TestCase):
	def validateLogin():
		login = requests.get("http://localhost:5000/login")
		assert(login.status_code == 200)
	def validateRegister():
		register = requests.get("http://localhost:5000/register")
		assert(register.status_code == 200)
	def validateSpellCheck():
		spell = requests.get("http://localhost:5000/spell_check")
		assert(spell.status_code == 200)

if __name__=='__main__':
	unittest.main()
from flask import Flask, flash, redirect, url_for, render_template, request, session, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm, CSRFProtect	
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, current_user, login_user, login_required
from flask_user import roles_required,UserManager
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import os
import subprocess
import sys
csrf = CSRFProtect()
app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'thisisthesecretkey'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf.init_app(app)

class User(db.Model):
	username = db.Column(db.String(15), unique=True, primary_key=True, nullable=False)
	password = db.Column(db.String(80), nullable=False)
	twofactor = db.Column(db.String(11), nullable=False)
	
	def __repr__(self):
		return f"User('{self.username}','{self.password}','{self.twofactor}')"

class RegisterForm(FlaskForm):
	username = StringField('username', id="uname", validators=[InputRequired(), Length(max=50)])
	password = StringField('password', id="pword", validators=[InputRequired(), Length(min=8, max=80)])
	twofactor = StringField('twofactor', id="2fa", validators=[InputRequired(), Length(min=11, max=11)])

class LoginForm(FlaskForm):
	username = StringField('username', id="uname", validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', id="pword", validators=[InputRequired(), Length(min=8, max=80)])
	twofactor = StringField('twofactor', id="2fa", validators=[InputRequired(), Length(min=11, max=11)])

class SpellCheckForm(FlaskForm):
	inputText = TextAreaField('input', id="inputtext", validators=[InputRequired(), Length(max=15000)])

db.drop_all()
db.create_all()

@app.route('/')
def home():
	if not session.get('logged_in'):
		return render_template('login.html')
	else:
		return "Hello!"

@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm()
	if request.method == 'POST' and form.validate():
		username = (form.username.data)
		password = (form.password.data)
		hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
		twofactor = (form.twofactor.data)
		if User.query.filter_by(username=('%s' % username)).first() == None:
			userToAdd = User(username=username, password=hashed_password, twofactor=twofactor)
			db.session.add(userToAdd)
			db.session.commit()
			msg="success"
			return render_template('register.html', form=form, msg=msg)
		else:
			userToAdd = User.query.filter_by(username=('%s' % username)).first()
			if username == userToAdd.username:
				msg='failure'
				return render_template('register.html', form=form, msg=msg)
	else:
		msg=''
		return render_template('register.html', form=form, msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if request.method == 'POST' and form.validate() and not session.get('logged_in'):
		username = (form.username.data)
		password = (form.password.data)
		hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
		twofactor = (form.twofactor.data)
		if User.query.filter_by(username=('%s' % username)).first() == None:
			msg='incorrect'
			return render_template('login.html', form=form, msg=msg)
		else:
			userCheck = User.query.filter_by(username=('%s' % username)).first()
			if username == userCheck.username and bcrypt.check_password_hash(userCheck.password, password) and twofactor==userCheck.twofactor:
				session['logged_in'] = True
				# userToAdd = User(username=username, password=hashed_password, twofactor=twofactor)
				# db.session.add(userToAdd)
				# db.session.commit()
				msg='success'
				return render_template('login.html', form=form, msg=msg)
			else:
				if bcrypt.check_password_hash(userCheck.password, password)==False:
					msg='Incorrect password'
					return render_template('login.html', form=form,msg=msg)
				if twofactor != userCheck.twofactor:
					msg='Two-Factor failure'
					return render_template('login.html', form=form,msg=msg)  

	if request.method == 'POST' and form.validate() and session.get('logged_in'): 
		msg='Already Logged In'
		return render_template('login.html', form=form,msg=msg)  
	else:
		msg=''
		return render_template('login.html', form=form,msg=msg)

@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
	form = SpellCheckForm()
	misspelled =[]

	if session.get('logged_in') and request.method == 'GET':
		msg=''
		return render_template('spell_check.html', form=form, msg=msg)

	if session.get('logged_in') and request.method == 'POST' and request.form['submit_button'] == 'Check':
		data = form.inputText.data
		myFile = open("myFile.txt", "w")
		myFile.write(data)
		myFile.close()
		#input = data
		arguments = ("./a.out", "myFile.txt", "wordlist.txt")
		try:
			popen = subprocess.Popen(arguments, stdout=subprocess.PIPE)
			popen.wait()
			output = popen.stdout.read()
			output = output.decode().replace("\n", ",")
			msg = "success"
		except subprocess.CalledProcessError as e:
			print("Error :", e)
			msg = "failure"
		return render_template('result.html', data=input, misspelled=output, msg=msg)

	if not session.get('logged_in'):
		msg='Not logged in'
		return render_template('spell_check.html', form=form,msg=msg)
	else:
		msg=''
		return render_template('spell_check.html', form=form, msg=msg)
	
if __name__ == "__main__":
	app.secret_key = os.urandom(12)
	app.run(debug=True,host='0.0.0.0', port=4000)
from flask import Flask, flash, redirect, url_for, render_template, request, session, abort
from flask_bootstrap import Bootstrap
from flask_wtf import Form, FlaskForm, CSRFProtect	
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, current_user, login_user, login_required
from flask_user import roles_required,UserManager
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import os
import subprocess
import sys
from datetime import * 

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
	level = db.Column(db.String(100))

	def __repr__(self):
		return f"User('{self.username}','{self.password}','{self.twofactor}')"

	def get_id(self):
		return self.username

	def get_active(self):
		return True

class History(db.Model):
	login_id = db.Column(db.Integer(),unique=True,nullable=False,primary_key=True,autoincrement=True)
	user_id = db.Column(db.Integer(),db.ForeignKey("user.username"),unique=False)
	username = db.Column(db.String(15), unique=False,nullable=False)
	action = db.Column(db.String(30))
	loggedIn = db.Column(db.DateTime)
	loggedOut = db.Column(db.DateTime)

	def __repr__(self):
		return f"History('{self.login_id}','{self.user_id}','{self.action}','{self.username}','{self.loggedIn}','{self.loggedOut}')"

class spellHistory(db.Model):
	queryID= db.Column(db.Integer(),unique=True,nullable=False,primary_key=True,autoincrement=True)
	username = db.Column(db.String(15), unique=False,nullable=False)
	querytext = db.Column(db.String(30000), unique=False,nullable=False)
	queryresults = db.Column(db.String(30000), unique=False,nullable=False)

	def __repr__(self):
		return f"spellHistory('{self.queryID}','{self.username}','{self.querytext}','{self.queryresults}')"

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

class historyForm(Form):
	textbox = TextAreaField('textbox', [validators.DataRequired(message="Enter Words to Check"), validators.Length(max=50000)], id='inputtext')



class wordForm(Form):
	textbox = TextAreaField('textbox', [validators.DataRequired(message="Enter Words to Check"),validators.Length(max=20000)], id='inputtext')
	

class userCheckForm(Form):
	textbox = TextAreaField('textbox', [validators.DataRequired(message="Enter User To Check Audit History"),validators.Length(max=20)], id='inputtext')
   

db.drop_all()
db.create_all()

adminToAdd = User(username='admin', password=bcrypt.generate_password_hash('Administrator@1').decode('utf-8'), twofactor='12345678901', level='admin')
db.session.add(adminToAdd)
db.session.commit()

@login_manager.user_loader
def user_loader(username):
	return userCreds.query.get(username)

@app.route('/')
def home():
	if not session.get('logged_in'):
		# form = LoginForm()
		# msg=" "
		# return render_template('login.html', form=form,msg=msg)
		return redirect(url_for("login"))
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
				userToAdd = History(action='LoggedIn', username=username,loggedIn=datetime.now())
				db.session.add(userToAdd)
				db.session.commit()
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

	if session.get('logged_in') and request.method =='POST' and request.form['submit_button'] =='Log Out':
		error='Logged Out'
		session.pop('logged_in', None)
		try:
			userLogOutToAdd = History(action='LoggedOut', username=current_user.username,loggedOut=datetime.now())
			db.session.add(userLogOutToAdd)
			db.session.commit()
			return render_template('login.html', error=error)
		except AttributeError:
			return render_template('login.html', error=error)


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

	if session.get('logged_in') and request.method =='POST' and request.form['submit_button'] =='Log Out':
		error='Logged Out'
		session.pop('logged_in', None)
		try:
			userLogOutToAdd = History(action='LoggedOut', username=current_user.username,loggedOut=datetime.now())
			db.session.add(userLogOutToAdd)
			db.session.commit()
			return render_template('spell_check.html', error=error)
		except AttributeError:
			return render_template('spell_check.html', error=error)

@app.route('/history', methods=['GET', 'POST'])
def history():
	form = historyForm(request.form)
	if session.get('logged_in') and request.method =='POST':
		try:
			uq = form.textbox.data
			print(uq)
			dbUserCheck = User.query.filter_by(username=('%s' % uq)).first()
			if dbUserCheck.accessRole=='admin':
				try:
					numqueries = spellHistory.query.filter_by(username=('%s' % uq)).order_by(spellHistory.queryID.desc()).first()
					allqs =  spellHistory.query.filter_by(username=('%s' % uq)).all()
					total = numqueries.queryID
				except AttributeError:
					numqueries = ''
					total = 0
					allqs = ''
				return render_template('history.html', numqueries=total,allqs=allqs,form=form)
		except AttributeError:
			return render_template('unauth.html')
	if session.get('logged_in') and request.method =='GET':
		try:
			numqueries = spellHistory.query.filter_by(username=('%s' % current_user.username)).order_by(spellHistory.queryID.desc()).first()
			allqs =  spellHistory.query.filter_by(username=('%s' % current_user.username)).all()
			total = numqueries.queryID
		except AttributeError:
			numqueries = ''
			total = 0
			allqs = ''
		return render_template('history.html', numqueries=total,allqs=allqs,form=form)
	else:
		return render_template('unauth.html')

@app.route("/history/<query>")
def queryPage(query):
	if request.method == 'GET':
		try:
			query = query.replace('query','')
			history = spellHistory.query.filter_by(queryID=('%s' % query)).first()
			queryID = history.queryID
			username = history.username
			submitText = history.text
			returnedText = history.results
		except AttributeError:
			return render_template('unauth.html')
		return render_template('queryIDresults.html', queryID=queryID, username=username,submitText=submitText,results=returnedText)

# Page for the Admin to retrieve login history of users 
@app.route('/login_history', methods=['GET','POST'])
def login_history():
	form = userCheckForm(request.form)
	try:
		dbUserCheck = User.query.filter_by(username=('%s' % current_user.username)).first()

		# if session.get('logged_in') and request.method =='GET' and dbUserCheck.accessRole=='admin':
		# 	error = 'Authenticated User '
		# 	return render_template('login_history.html', form=form, error=error)
	
		if request.method == 'GET':
			return render_template('login_history.html', form=form, error=error)
		if session.get('logged_in') and request.method == 'POST' and request.form['submit_button'] == 'Check User Login History':
			userToQuery = (form.textbox.data)
			results = History.query.filter_by(username=('%s' % userToQuery)).all()
			return render_template('login_history_results.html', misspelled=results)
		else:
			error='Please Login As Admin'
			return render_template('login_history.html', form=form, error=error)
	except:
		error=''
		return render_template('login_history.html', form=form, error=error)

	
if __name__ == "__main__":
	app.secret_key = os.urandom(12)
	app.run(debug=True,host='0.0.0.0', port=4000)
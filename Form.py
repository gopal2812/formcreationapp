import os
import time
import re
import glob
import json
from flask import Flask, render_template, flash, request
from flask.helpers import url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, RadioField
from wtforms.validators import DataRequired, EqualTo, Length, URL
from wtforms.fields.core import FieldList, IntegerField, SelectField
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug import datastructures
from werkzeug.utils import redirect
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

#Create a flask instance
app = Flask(__name__)
#Add sqlite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
#Secret Key
app.config['SECRET_KEY'] = 'secret'
#Initialize the DB
db = SQLAlchemy(app)
#Migrate our app with db
migrate = Migrate(app, db)

# Flask login requisites
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#Create Model to register users
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    role = db.Column(db.String(20),nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    # Password stuff...
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        print('trying to read pwd')
        raise AttributeError('Password is not a readable item !')

    @password.setter
    def password(self, password):
        print('Inside pwd setter', password)
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        print('Inside verify pwd', password)
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Name %r>' % self.name

# Create a login form
class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create a Form class that can feed our db for users registered
class UserForm(FlaskForm):
    name = StringField("Name", validators = [DataRequired()])
    username = StringField("Username", validators = [DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    role = StringField("User Role",  validators=[DataRequired()])     #No validators for favorite color
    password_hash = PasswordField('Password', validators=[DataRequired(),
                                                          EqualTo('password_hash2', message='Passwords must match !')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create a Form class for password
class PasswordForm(FlaskForm):
    email = StringField("Enter your email ID", validators = [DataRequired()])
    password_hash = PasswordField("Enter your password", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create a Form class
class NamerForm(FlaskForm):
    name = StringField("What's your name?", validators = [DataRequired()])
    submit = SubmitField("Submit")

class QuestionForm(FlaskForm):
	question_name=StringField("Please write the question to be asked in Form",validators=[DataRequired()])
	question_type=SelectField("Choose the question Type?",choices=[
    ("mcq", "Multiple Choice Questions"),
    ("MulAns", "Multiple Answers"),
    ("PhoNum", "Phone Number"),
    ("SText", "Short Text"),
    ("LText", "Long Text"),
    ("PMCQ", "Picture Multiple Choice Questions"),
    ("PMA", "Picture Multiple Answers"),
    ("stmt", "Statement"),
    ("bool", "Yes/No"),
    ("email", "Email"),
    ("Lkrt", "Likert"),
    ("Rtg", "Rating"),
    ("date", "Date"),
    ("int", "Number"),
    ("fitb", "Fill in the blank"),
    ("fitbs", "Fill in the blanks"),
    ("drpdwn", "Dropdown"),
    ("wbst", "Website")])
	required=BooleanField('Required Question',validators=[DataRequired()])
	image_link=StringField('Image URL',validators=[URL()])
	question_layout=RadioField('Layout',choices=[('above','Image above question'),('side','Image on the side of the question')])
	# if question_type=="mcq":
	# 	name=StringField('hi')
	submit=SubmitField("Submit")

class ProductForm(FlaskForm):
    choice_1 = StringField('Choice 1')
    choice_2 = StringField('Choice 2')
    choice_3 = StringField('Choice 3')
    choice_4 = StringField('Choice 4')

class MCQForm(FlaskForm):
	choices=FieldList(StringField('Choice'),label="Answer choices",min_entries=4,max_entries=4)
	correct_choice=IntegerField('Correct choice index',validators=[DataRequired()])
	submit=SubmitField('Submit')

class OneMoreQuestion(FlaskForm):
	yesonemore=BooleanField('Add one more question?')
	submit=SubmitField("Submit")

class FormName(FlaskForm):
    yesonemore = StringField("What is the name of the form?", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create login page
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # Check the hashed password
            if check_password_hash(user.password_hash, form.password.data):
                # form.password.data -> user supplied pwd, user.password_hash -> hashed pwd stored in DB for this username
                # if both these matches , then login successful
                login_user(user)
                flash('Login successful !')
                return redirect(url_for('dashboard'))
            else:
                flash('Password incorrect - please give correct password')
        else:
            flash('Username - doesnt exist. Please try again with correct username')

    return render_template('login.html', form=form)

#forms edit
@app.route("/forms/edit/<hash>")
def edit_form(hash):
	try:
		with open(f"forms/{hash}.json",encoding='utf-8') as filequiz:
			return "\n".join(filequiz.readlines())
	except OSError:
		return "An error occurred with the file name passed"

#form hash
@app.route("/forms/<hash>")
def form(hash):
	try:
		with open(f"forms/{hash}.json",encoding='utf-8') as filequiz:
			return "\n".join(filequiz.readlines())
	except OSError:
		return "An error occurred with the file name passed"

# Create logout page
@app.route('/logout',methods=['GET','POST'])
@login_required # We can't logout unless logged-in
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('login'))

@app.route("/forms/create",methods=['GET','POST'])
def create_form():
	form=QuestionForm()
	if form.validate_on_submit():
		global details_dict
		details_dict=form.data
		if form.question_type.data=="mcq":
			return redirect("/forms/create-mcq")
	return render_template('create-form.html', form=form)

@app.route("/forms/create-mcq",methods=['GET','POST'])
def create_mcq():
	try:
		if not details_dict:
			return redirect("/dashboard")
	except:
		return redirect("/dashboard")
	choiceform=MCQForm()
	if choiceform.validate_on_submit():
		correct=choiceform.correct_choice.data-1
		choices=choiceform.choices.data
		choices=[x for x in choices if x.strip()]
		if correct>len(choices):
			flash("Correct choice not within bounds")
			choiceform.correct_choice.data=None
		elif len(choices)==1:
			flash("Only one unique choice exists!")
		else:
			details_dict.update({'choices':choices,'correct':correct})
			return redirect('/forms/create-new')
	return render_template('mcq.html',form=choiceform)

@app.route("/forms/create-new", methods=['GET', 'POST'])
def next_question():
    global q_list
    try:
        if q_list:
            pass
    except:
        q_list = []

    OneMore = OneMoreQuestion()
    if OneMore.is_submitted():
        print("ji")
        q_list.append(details_dict)
        print(details_dict)
        if OneMore.yesonemore.data == True:
            return redirect('/forms/create')
        else:
            return redirect("/forms/name-setter")

    return render_template("nextquestion.html", form=OneMore)

@app.route('/forms/name-setter',methods=['GET','POST'])
def nameform():
	nameform=FormName()
	if nameform.validate_on_submit():
		details_dict['name']=nameform.yesonemore.data
		if os.path.isfile(details_dict['name']):
			flash("That name has already been used")
		else:
			with open(f"forms/{details_dict['name']}.json","w") as file:
				json.dump(q_list,file)
			return redirect("/dashboard")
	return render_template("namesetter.html",form=nameform)


# Create dashboard page
@app.route('/dashboard',methods=['GET','POST'])
@login_required  # This will help reroute back to login page if not logged-in
def dashboard():
    content = [f"{url_for('edit_form', hash=x.split('.')[0])}" for x in os.listdir('./forms')]
    return render_template('dashboard.html', files=os.listdir("./forms"))

# Delete an existing User from list
@app.route('/delete/<int:id>')
def delete(id):
    name = None
    form = UserForm()
    user_to_delete = Users.query.get_or_404(id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully')
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html",
                               form=form,
                               name=name,
                               our_users=our_users)
    except:
        flash('Error in Deleting the record!')
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html",
                               form=form,
                               name=name,
                               our_users=our_users)


# Update Database record for existing user
@app.route('/update/<int:id>', methods=['GET','POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.role = request.form['role']
        try:
            db.session.commit()
            flash('User Updated successfully')
            return render_template('update.html',
                                   form=form,
                                   name_to_update = name_to_update,
                                   id = id)
        except:
            flash('Error in Updating the records!')
            return render_template('update.html',
                                   form=form,
                                   name_to_update = name_to_update,
                                   id =id)
    else:
        return render_template('update.html',
                               form=form,
                               name_to_update=name_to_update,
                               id =id)

# Add a new user
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()  #This shouldn't return any result as email need to be unique
        if user is None:   #if user is None, then execute logic to add new user
            hashed_pwd = generate_password_hash(form.password_hash.data, 'sha256') # We are passing password entered in form to be converted to hash
            user = Users(name=form.name.data, username=form.username.data,
                         email=form.email.data, role=form.role.data,
                         password_hash=hashed_pwd)  # Here is where we are saving to database, so pass hashed_pwd here so that hashed password gets saved in database
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.role.data = ''
        form.password_hash.data = ''
        flash("User Added Successfully!")

    our_users = Users.query.order_by(Users.date_added)
    return render_template("add_user.html",
                           form = form,
                           name = name,
                           our_users=our_users)

#Create route decorator
@app.route('/')

def index():
    message = ' <strong> Welcome...If new user, Please go to Register tab to sign-up </strong>'
    return render_template("index.html",
                           message = message
                           )

@app.route('/user/<name>')
def user(name):
#   return "<h1>Hello {} !!! </h1>" .format(name)
    return render_template('user.html', user_name=name)

#Create custom error pages

#Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#Internal server error
@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500

#Create Name Page
@app.route('/name',methods=['GET', 'POST'])
def name():
    name = None
    form = NamerForm()
    # Validate Form
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''

    return render_template('name.html',
                           name=name,
                           form=form)
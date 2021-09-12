import os
import time
import re
import glob
import json
from types import LambdaType
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
        image_link=StringField('Image URL',validators=[URL()])
        question_layout=SelectField('Select the image Layout',choices=[('above','Image above question'),('side','Image on the side of the question')])
        submit=SubmitField("Submit")

class CreateForm(FlaskForm):
        total_marks=IntegerField("Total marks for the test",validators=[DataRequired()])
        total_time=IntegerField('Duration limit of the test',validators=[DataRequired()])

class ProductForm(FlaskForm):
    choice_1 = StringField('Choice 1')
    choice_2 = StringField('Choice 2')
    choice_3 = StringField('Choice 3')
    choice_4 = StringField('Choice 4')

class MCQForm(FlaskForm):
        choices=FieldList(StringField('Choice'),label="Answer choices",min_entries=4,max_entries=4)
        correct_choice=IntegerField('Correct choice index',validators=[DataRequired()])
        submit=SubmitField('Submit')

#class OneMoreQuestion(FlaskForm):
#        yesonemore=BooleanField('Add one more question?')
#        submit=SubmitField("Submit")

class OneMoreQuestion(FlaskForm):
        yesonemore = RadioField('Add one more question?', choices = [(True, 'Add more question'),
                                                                     (False, 'Complete the Form')])
        submit = SubmitField("Submit")

class MultipleAnswer(FlaskForm):
        choices=FieldList(StringField(label='Choice',validators=[DataRequired()]),
                      label='Choices',min_entries=4, max_entries=4)
        correct_choices=IntegerField('Correct choice index number', validators=[DataRequired()])
        submit=SubmitField("Submit")

class PictureMCQForm(FlaskForm):
        choices=FieldList(StringField('Choice'), label="test", min_entries=4, max_entries=4)
        correct_choice=IntegerField('Correct choice index number', validators=[DataRequired()])
        image_link=StringField(label='IMAGE URL', validators=[DataRequired(),URL(),
                                                              lambda x:x.endswith(('png','jpeg','jpg'))])
        question_layout=RadioField('Layout ', choices=[('above','Image above question'), ('side','Image on the side of the question')])
        submit=SubmitField('Submit')

class PictureMultipleChoicesForm(FlaskForm):
        choices=FieldList(StringField(label='Choice', validators=[DataRequired()]),label='Choices',min_entries=4,max_entries=4)
        correct_choices=IntegerField('Correct choice index',validators=[DataRequired()])
        image_link=StringField(label='IMAGE URL', validators=[DataRequired(), URL(), lambda x:x.endswith(('png','jpeg','jpg'))])
        question_layout=RadioField('Layout ', choices=[('above','Image above question'), ('side','Image on the side of the question')])
        submit=SubmitField('Submit')

class LikertForm(FlaskForm):
        choices=FieldList(StringField(label='Likert option', validators=[DataRequired()]),label='Choices',min_entries=4,max_entries=4)
        rating_choices=FieldList(StringField(label='Choice', validators=[DataRequired()]),label='Rating strings',min_entries=4,max_entries=4)
        submit=SubmitField('Submit')

class FillInOneBlank(FlaskForm):
        sentence=StringField("What is the sentence? (Please indicate the blank with a series of underscores)",validators=[DataRequired()])
        blank=StringField("What is the correct blank/answer?", validators=[DataRequired()])
        submit=SubmitField("Submit")

class FillinTheBlanks(FlaskForm):
        sentence=StringField("What is the sentence? (Please indicate the blank with two consecutive '$' signs)",validators=[DataRequired()])
        blank=FieldList(StringField("What is the correct blank/answer according to the order?",
                                    validators=[DataRequired()]), label="Blanks", min_entries=5, max_entries=7)
        submit=SubmitField('Submit')

class Dropdown(FlaskForm):
        choices=FieldList(StringField(label='Choice', validators=[DataRequired()]),
                          label='Dropdown choices', min_entries=4,max_entries=4)
        correct_choice=IntegerField('Correct choice index number',validators=[DataRequired()])
        submit=SubmitField('Submit')

class FileUpload(FlaskForm):
        FileNameShouldEndWith=StringField(label='What is the file extension required to be?', validators=[DataRequired()])
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
                elif form.question_type.data == "mulans":
                    return redirect("/forms/ma")
                elif form.question_type.data == "PMCQ":
                    return redirect("/forms/pmcq")
                elif form.question_type.data == "PMA":
                    return redirect("/forms/pma")
                elif form.question_type.data == "Lkrt":
                    return redirect("/forms/likert")
                elif form.question_type.data == "fitb":
                    return redirect("/forms/fiob")
                elif form.question_type.data == "fitbs":
                    return redirect("/forms/fitb")
                elif form.question_type.data == "drpdwn":
                    return redirect("/forms/drpdwn")
                elif form.question_type.data == "upl":
                    return redirect("/forms/upl")
                else:
                    return redirect('/forms/create-new')
        return render_template('create-form.html', form=form)

@app.route("/forms/create-mcq",methods=['GET','POST'])
def create_mcq():
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

@app.route("/forms/ma",methods=['GET','POST'])
def create_ma():
        global details_dict
        choiceform=MultipleAnswer()
        if choiceform.validate_on_submit():
                correct_choices=choiceform.correct_choices.entries
                choices=choiceform.choices.data
                choices=[x for x in choices if x.strip()]
                if len(choices)==0 or len(choices)==1:
                        flash("Please enter more than one unique choice.")
                if len(correct_choices)>len(choices):
                        flash("There are more correct choices than the choices!")
                else:
                        details_dict.update({'choices':choices,'correct':correct_choices})
                        return redirect('/forms/create-new')
        return render_template('MA.html',form=choiceform)

@app.route("/forms/pmcq",methods=['GET','POST'])
def create_pmcq():
        global details_dict
        choiceform=PictureMCQForm()
        if choiceform.validate_on_submit():
                correct=choiceform.correct_choice.data-1
                choices=choiceform.choices.data
                imagelink=choiceform.image_link.data
                layout=choiceform.question_layout.data
                choices=[x for x in choices if x.strip()]
                if correct>len(choices):
                        flash("Correct choice not within bounds")
                elif len(choices)==1:
                        flash("Only one unique choice exists!")
                else:
                        details_dict.update({'choices':choices,'correct':correct,'image_link':imagelink,'layout':layout})
                        return redirect('/forms/create-new')
        return render_template('mcq.html',form=choiceform)

@app.route("/forms/pma",methods=['GET','POST'])
def create_pma():
        global details_dict
        choiceform=PictureMultipleChoicesForm()
        if choiceform.validate_on_submit():
                correct_choices=choiceform.correct_choices.entries
                choices=choiceform.choices.data
                image_link=choiceform.image_link.data
                layout=choiceform.question_layout.data
                choices=[x for x in choices if x.strip()]
                if len(choices)==0 or len(choices)==1:
                        flash("Please enter more than one unique choice.")
                if len(correct_choices)>len(choices):
                        flash("There are more correct choices than the choices!")
                else:
                        details_dict.update({'choices':choices,'correct':correct_choices,'image_link':image_link,'layout':layout})
                        return redirect('/forms/create-new')
        return render_template('PMA.html',form=choiceform)

@app.route('/forms/likert',methods=['GET','POST'])
def create_likert():
        global details_dict
        choiceform=LikertForm()
        if choiceform.validate_on_submit():
                choices=choiceform.choices.data
                rating_choices=choiceform.rating_choices.data
                choices=[x for x in choices if x.strip()]
                details_dict.update({'choices':choices,'rating_choices':rating_choices})
                return redirect('/forms/create-new')
        return render_template('likert.html',form=choiceform)

@app.route('/forms/fiob',methods=['GET','POST'])
def create_FIOB():
        global details_dict
        choiceform=FillInOneBlank()
        if choiceform.validate_on_submit():
                sentence=choiceform.sentence.data
                blank=choiceform.blank.data
                if "$$" not in sentence:
                        flash("There is no blank present in the sentence")
                elif sentence.count("$$")>1:
                        flash("Only one blank is needed!")
                details_dict.update({'sentence':sentence,'blank':blank})
                return redirect('/forms/create-new')
        return render_template('FIOB.html',form=choiceform)

@app.route('/forms/fitb',methods=['GET','POST'])
def create_FITB():
        choiceform=FillinTheBlanks()
        if choiceform.validate_on_submit():
                sentence=choiceform.sentence.data
                blank=choiceform.blank.data
                if "$$" not in sentence:
                        flash("There is no blank present in the sentence")
                elif len(blank)!=sentence.count("$$"):
                        flash("Something is wrong with the number of blanks or sentence")
                details_dict.update({'sentence':sentence,'blank':blank})
                return redirect('/forms/create-new')
        return render_template('FIOB.html',form=choiceform)

@app.route('/forms/dd',methods=['GET','POST'])
def create_dd():
        choiceform=Dropdown()
        if choiceform.validate_on_submit():
                rawchoices=choiceform.choices.data
                choices=[]
                for choice in rawchoices:
                        if choice not in choices:
                                choices.append(choice.strip())
                correct_choice=choiceform.correct_choice.data-1
                if correct_choice>len(choices):
                        flash("You've entered an incorrect index for the correct choice")
                elif correct_choice<0:
                        flash("Positive indexes only.")
                details_dict.update({'choices':choices,'correct':correct_choice})
                return redirect('/forms/create-new')
        return render_template('MCQ.html',form=choiceform)

@app.route('/forms/upload',methods=['GET','POST'])
def create_upload():
        global logged_in_as
        try:
                if not logged_in_as:
                        return redirect("/")
                try:details_dict
                except NameError:return redirect("/")
        except:
                return redirect("/")
        choiceform=FileUpload()
        if choiceform.validate_on_submit():
                file_ext=choiceform.FileNameShouldEndWith.data
                file_ext=file_ext.split()
                details_dict.update({'file_ext':file_ext})
                return redirect('/forms/create-new')
        return render_template('FIOB.html',form=choiceform)

@app.route("/forms/create-new", methods=['GET', 'POST'])
def next_question():
    global q_list
    global details_dict
    try:
        if q_list:
            pass
    except:
       q_list = []

    OneMore = OneMoreQuestion()
    if OneMore.is_submitted():
        q_list.append(details_dict)
        print(details_dict)
        #print("hi")
        #print(strOneMore.yesonemore.data)
        if OneMore.yesonemore.data == 'True':
            print("redirect to create" + str(OneMore.yesonemore.data))
            return redirect('/forms/create')
        else:
            return redirect("/forms/name-setter")

    return render_template("nextquestion.html", form=OneMore)

@app.route('/forms/name-setter',methods=['GET','POST'])
def nameform():
    nameform = FormName()
    if nameform.validate_on_submit():
        global details_dict
        global q_list
        details_dict.update({'name': nameform.yesonemore.data})
        if os.path.isfile(f"forms/{nameform.yesonemore.data}.json"):
            flash("That name has already been used")
        else:
            with open(f"forms/{details_dict['name']}.json", "w") as file:
                json.dump(q_list, file)
                q_list = []
                details_dict = {}
                print("redirection dashboard stuck %s", file)
                #return redirect("/")
                return redirect(url_for('dashboard'))
    return render_template("namesetter.html", form=nameform)


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

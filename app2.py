from ast import Str
from crypt import methods
from enum import unique
from re import L
import sqlite3
from sre_parse import GLOBAL_FLAGS
import bcrypt
from flask import Flask, render_template, request, session, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
current_dir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + os.path.join(current_dir, "database.sqlite3")
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    #all = db.relationship('All')

class list(db.Model):
   __tablename__ = 'list'
   id = db.Column(db.Integer, primary_key = True)
   name=db.column(db.String(20))
   description=db.column(db.String(20))
   user_id = db.Column(db.Integer, db.ForeignKey('user.id'))    

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        
        if existing_user_username:
            raise ValidationError("Username already in use. Please choose another one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

    

@app.route('/')
def home():
    return render_template("home.html")
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template("login.html", form = form)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    #lists = db.session.query(list.name).filter(list.user_id == current_user.id).distinct()
    user = current_user.username
    return render_template("dashboard.html", user = user)

@app.route('/register',  methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
        
    return render_template("register.html", form = form)    

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/addNewList', methods=['GET', 'POST'])
@login_required
def addNewList():
    user = current_user.username
    form = ListForm()
    current_user_id = current_user.id
    if form.validate_on_submit():
        new_List = list(user_id = current_user_id,name=form.name.data, description = form.Description.data)
        db.session.add(new_List)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template("list.html", form = form, user = user)


if __name__ == '__main__':
    app.run(debug=True)

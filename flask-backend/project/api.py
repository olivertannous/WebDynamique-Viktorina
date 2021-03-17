from flask import Flask, Response
from flask_sqlalchemy import SQLAlchemy
from flask import render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, LoginManager 
from flask_cors import CORS
from flask import jsonify,make_response
import sys
import json
from secrets import *
 

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    CORS(app)
    app.config['CORS_HEADERS'] = 'Content-Type'

    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://{user}:{password}@{server}/{database}'.format(user=secrets.user, password=secrets.password, server=secrets.server, database=secrets.database)
   

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
   
app = create_app()

@app.route('/',methods=['POST', 'GET'])
def home():
    return redirect(url_for("http://localhost:3000/home"))


@app.route('/signin',methods=['POST', 'GET'])
def login():
   from models import User
   email = request.form.get('email')
   password = request.form.get('password')
   remember = True if request.form.get('remember') else False
   #Get user from DB check credentials
   user = User.query.filter_by(email=email).first()
   if not user or not check_password_hash(user.password, password): 
      return render_template('LoginFailed.html')
   login_user(user, remember=remember)
   render_template('PostLogin.html')
   response = make_response(jsonify({"username": user.fname}),200,)
   response.headers["Content-Type"] = "application/json"
   return response

@app.route('/signup', methods=['POST'])
def signup_post():
    from models import User

    email = request.form.get('email')
    lastname = request.form.get('lastName')
    firstname=request.form.get('firstName')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user:  
        flash('Email address already exists')
        return redirect(url_for('Home'))

    # Create user and hash PW
    new_user = User(email=email, fname=firstname,lname=lastname, password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    return render_template('PostRegistration.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return Response("{user logged out}", status=200, mimetype='application/json')

@app.route('/generate-questions',methods=['POST','GET'])
def generate_questions():
    from pipelines import pipeline
    print('Getting the text to analyse', file=sys.stderr)
    text2=request.form['togenerate']
    print('got the get to analyse below', file=sys.stderr)
    print(text2, file=sys.stderr)
    print('Starting to generate questions', file=sys.stderr)
    nlp = pipeline("question-generation")
    res= nlp(text2)
    response = make_response(jsonify(res),200,)
    response.headers["Content-Type"] = "application/json"
    return response
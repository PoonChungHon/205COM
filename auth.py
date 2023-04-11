from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'] )
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password') 

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('login successful', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Password are incorrect, please try again', category='error') 
        else:
            flash('This email does not exist', category='error')           

    return render_template("login.html", user=current_user)
#initiating websites

@auth.route('/shoppage')
def shoppage():
    return (url_for('shoppage.html'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/signup', methods=['GET', 'POST'] )
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        firstName = request.form.get('firstName')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Emil is already in use')
        if len(email) < 5:
            flash('email length must be 4 characters or more', category='error')

        elif len(firstName) < 2:
            flash('First Name length must be 2 characters or more', category='error')

        elif password1 != password2:
            flash('passwords ar not identical toeachother', category='error')

        elif len(password1) < 8:
            flash('password length must be 8 characters or more', category='error')
            
        else:
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account successfully created!', category='success')
            return redirect(url_for('views.home'))

            # users are added nto the database


    return render_template("signup.html", user=current_user)



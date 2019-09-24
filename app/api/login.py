from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user
from app.models.breaches import *
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
    )
from app.util.hash import *
@get('/login')
def login():
    return template('login')
def is_comprimised_accounts(db, username, password):
   plaintext_breaches, hashed_breaches, salted_breaches = get_breaches(db, username)
   for entry in plaintext_breaches:
     dic_format = entry.__dict__
     if(password == dic_format["password"]):
         return True
   for entry in hashed_breaches:
       dict_format = entry.__dict__
       if (hash_sha256(password) == dict_format["hashed_password"]):
         return True
   for entry in salted_breaches:
       dict_format = entry.__dict__
       if (hash_pbkdf2(password, dict_format["salt"]) == dict_format["salted_password"]):
           return True
   return False

@post('/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    error = None
    user = get_user(db, username)
    print(user)
    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)
        elif user.password != hash_pbkdf2(password, user.salt):
            response.status = 401
            error = "Wrong password for {}.".format(username)
        else:
            pass  # Successful login
    elif (request.forms.get("register")):
        if user is not None:
            response.status = 401
            error = "{} is already taken.".format(username)
        else:
            if not is_comprimised_accounts(db, username, password): 
                create_user(db, username, password)
            else:
                response.status = 401
                error = "Attempted password for {} has been found in breached database .".format(username)
    else:
        response.status = 400
        error = "Submission error."
    if error is None:  # Perform login
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", str(session.get_id()))
        return redirect("/{}".format(username))
    return template("login", error=error)

@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")



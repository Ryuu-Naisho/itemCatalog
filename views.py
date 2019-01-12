#!/usr/bin/env python3

#from redis import Redis
#import time
from functools import update_wrapper
from flask import abort, Flask, flash, g, jsonify, make_response, render_template, request, url_for
from flask import session as login_session
from models import Base, Category, Item, User
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
import httplib2
import json, random, requests, string
from pip._vendor.urllib3 import response
from flask.wrappers import Response
from werkzeug.utils import redirect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

engine = create_engine('sqlite:///itemCatalog.db', connect_args={'check_same_thread':False})

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

#TODO create verify_password or token method HERE

@app.route('/login')
def login():
    ''' Returns the client html where to login through oAuth '''
    
    ''' CSRF TOKEN '''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in  range(32))
    login_session['state'] = state
    return render_template('login.html', client_id = CLIENT_ID,STATE = state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    ''' Google auth '''
    
    ''' Check CSRF TOKEN exists. '''
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid State Parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response 
    
    ''' Google authorization code. '''
    code = request.data
    
    ''' Convert Google authorization code into credentials object. '''
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    ''' Validate access token. '''
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.format(access_token))
    h = httplib2.Http()
    # Reference .decode() suer Alexander Frolov https://stackoverflow.com/questions/51259636/httplib2-http-typeerror-the-json-object-must-be-str-not-bytes
    result = json.loads((h.request(url, 'GET')[1]).decode())
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    ''' Validate credentials authenticity. '''
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match the given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    ''' Validate access token is meant for this app '''
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    ''' Validate user is not already connected. '''
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),200)
        response.headers['Content-Type'] = 'application/json'
        return response  
    
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    
    ''' Get user info '''
    user_info_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token' : credentials.access_token, 'alt' : 'json'}
    incoming_response = requests.get(user_info_url, params = params)
    
    user_info = incoming_response.json()
    
    login_session['username'] = user_info['name']
    login_session['picture'] = user_info['picture']
    login_session['email'] = user_info['email']
    
    flash('Welcome {}'.format(login_session['username']))
    return 'Success'

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    
    ''' Validate user is already logged out. '''
    if access_token is None:
        response = make_response(json.dumps("There's nothing to log out off."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(login_session['access_token'])
    http_get = httplib2.Http()
    response = http_get.request(url,'GET')[0]
    ''' Remove session tokens. '''
    if response['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(
            json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect('/')
    else:
        response = make_response(
            json.dumps('Failed to revoke token.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/')
@app.route('/home')
def home():
    ''' Returns to home template. Requires user to be logged in. '''
    
    items = session.query(Item).all()
    category = session.query(Category).all()
    #TODO return to home.html with item and catalog variables
    return render_template('home.html', categories = category, items = items)

@app.route('/categories/<string:category_name>')
def getCategory(category_name):
    ''' Returns the category template and displays items that belong to the category. '''
       
    category = session.query(Category).filter_by(name = category_name).first()
    items = session.query(Item).filter_by(category_id = category.id).all()
    
    ''' Redirect traffic for users and non-users '''
    if 'username' in login_session:
        return render_template('user_category.html', category_name = category_name, items = items)
    else:
        return render_template('category.html', category_name = category_name, items = items)

@app.route('/categories/<string:category_name>/edit')
def editCategory(category_name):
    ''' Edit Category, user must be owner. '''
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    return category_name
@app.route('/categories/<string:category_name>/delete')
def deleteCategory(category_name):
    ''' Delete Category, user must be owner. '''
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    
    return category_name

@app.route('/items/<string:item_name>')
def getItem(item_name):
    ''' Returns the item template and displays item and description. '''
    
    ''' Clean up item_name. '''
    name = item_name.replace('%','')
    item = session.query(Item).filter_by(name = name).first()
    category = session.query(Category).filter_by(id = item.category_id).first()
    
    ''' Redirect traffic for users and non-users '''
    if 'username' in login_session:
        return render_template('user_item.html', item = item, category_name = category.name)
    else:
        return render_template('item.html', item = item, category_name = category.name)
@app.route('/items/<string:item_name>/edit')
def editItem(item_name):
    ''' Edit items, user must be owner. '''
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    
    return item_name

@app.route('/items/<string:item_name>/delete')
def deleteItem(item_name):
    ''' Delete Items, user must be owner. '''
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    
    return item_name

@app.route('/logout')
def logout():
    ''' Logs a user out. '''
    
    if 'username' not in login_session:
        return redirect('/login')
    
    if 'gplus_id' in login_session:
        return gdisconnect()

def isOwner(entryUserID):
    ''' Checks if the logged-in user is owner of an entry. '''
    try:
        loggedInUserID = session.query(User).filter_by(email = login_session['email']).first()
        
        if loggedInUserID is entryUserID:
            return true
        else:
            return false
    except : 
        return 'No user is logged in'
    
#@TODO Add Edit, Create, and delete function to  items and category

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
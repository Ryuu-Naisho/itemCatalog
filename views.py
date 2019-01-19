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

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    ''' Facebook oAuth. '''
    
    ''' Make sure CSRF Token exists. '''
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    access_token = request.data
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id={}&client_secret={}&fb_exchange_token={}'.format(
        app_id, app_secret, access_token)
    '''@ TODO FIX access_token not valid '''
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    
    '''Get user info. '''
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.decode().split(',')[0].split(':')[1].replace('"', '')
    url = 'https://graph.facebook.com/v2.8/me?access_token={}&fields=name,id,email'.format(token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result.decode())
    if data['error']:
        return "Couldn't connect to Facebook."
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] =  data['id']
    login_session['access_token'] = token
    
    ''' Get user picture. '''
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token={}&redirect=0&height=200&width=200'.format(token)
    h = httplib2.Http()
    result = h.request(url,'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data['data']['url']
    
    ''' See if user exists. '''
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    
    flash("Welcome {}".format(login_session['username']))
    return 'Success.'

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token={}'.format(facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    del login_session['provider']
    del login_session['username']
    del login_session['email']
    del login_session['facebook_id']
    del login_session['access_token']
    del login_session['picture']
    return redirect('/')
    
    
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

    if not userExists(user_info['email']):
        createUser(user_info['name'], user_info['email'], user_info['picture'], login_session['access_token'])
    
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
    return render_template('home.html', categories = category, items = items, user = getUser())

@app.route('/categories/<string:category_name>')
def getCategory(category_name):
    ''' Returns the category template and displays items that belong to the category. '''
       
    category = session.query(Category).filter_by(name = category_name).first()
    items = session.query(Item).filter_by(category_id = category.id).all()
    
    ''' Redirect traffic for users and non-users '''
    if 'username' in login_session:
        return render_template('user_category.html', category_name = category_name, items = items, user = getUser())
    else:
        return render_template('category.html', category_name = category_name, items = items, user = False)

@app.route('/categories/<string:category_name>/edit', methods=['GET','POST'])
def editCategory(category_name):
    ''' Edit Category, user must be owner. '''
    category = session.query(Category).filter_by(name = category_name).first()
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    
    if request.method == 'POST':
        category.name = request.form['name']
        session.commit()
        flash('{} has been updated.'.format(request.form['name']))
        return redirect('/categories/{}'.format(category.name))
    
    return render_template('edit_category.html', category_name = category_name, user = getUser())
    
    return category_name
@app.route('/categories/<string:category_name>/delete', methods=['GET','POST'])
def deleteCategory(category_name):
    ''' Delete Category, user must be owner. '''
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    
    if request.method == 'POST':
        category = session.query(Category).filter_by(name = category_name).first()
        session.delete(category)
        session.commit()
        flash('{} has been deleted.'.format(category_name))
        return redirect('/')
    
    return render_template('delete_category.html', category_name = category_name, user = getUser())

@app.route('/categories/new', methods=['GET','POST'])
def createCategory():
    ''' Create a new category. '''
    
    ''' Restrict access to users not logged in.'''
    if 'username' not in login_session:
        return redirect('/login')
    
    if request.method =='POST':
        category = Category(name = request.form['name'])
        session.add(category)
        session.commit()
        
        return redirect('/')
    
    return render_template('create_category.html', user = getUser())

@app.route('/items/<string:item_name>')
def getItem(item_name):
    ''' Returns the item template and displays item and description. '''
    
    item = session.query(Item).filter_by(name = item_name).first()
    try:
        category = session.query(Category).filter_by(id = item.category_id).first()
    except AttributeError:
        return render_template('404.html', user = getUser(), message = 'Item {} not found'.format(item_name))
        
    ''' Redirect traffic for users and non-users '''
    if 'username' in login_session and isOwner(item.user_id):
        return render_template('user_item.html', item = item, category_name = category.name, user = getUser())
    elif 'username' in login_session and not isOwner(item.user_id):
        return render_template('item.html', item = item, category_name = category.name, user = getUser())
    else:
        return render_template('item.html', item = item, category_name = category.name, user = False)
@app.route('/items/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(item_name):
    ''' Edit items, user must be owner. '''
    
    item = session.query(Item).filter_by(name = item_name).first()
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    
    ''' Restrict access to logged users whom items not belong. '''
    if not isOwner(item.user_id):
        return redirect('/')
    
    if request.method == 'POST':
        
        formName = request.form['name']
        formDescription = request.form['description']
        formCategoryID = request.form['category']
        
        ''' Check which fields have been updated then update. '''
        if formName is not item.name:
            item.name = formName
        if formDescription is not '':
            item.description = formDescription
        if formCategoryID is not item.category_id:
            item.category_id = formCategoryID
        session.commit()
        flash('{} has been updated.'.format(formName))
        
        return redirect('/')
    else:
        thisCategory = session.query(Category).filter_by(id = item.category_id).first()
        categories = session.query(Category).all()
        return render_template('edit_item.html', item = item, category_name = thisCategory.name, categories = categories, user = getUser())

@app.route('/items/<string:item_name>/delete', methods=['GET','POST'])
def deleteItem(item_name):
    ''' Delete Items, user must be owner. '''
    
    item = session.query(Item).filter_by(name = item_name).first()
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    
    ''' Restrict access to logged users whom items not belong. '''
    if not isOwner(item.user_id):
        return redirect('/')
    
    if request.method  == 'POST':
        session.delete(item)
        session.commit()
        flash('{} was deleted.'.format(item_name))
        return redirect('/')
    else:
        return render_template('delete_item.html', item = item, user = getUser())

@app.route('/items/<string:category_name>/new', methods=['GET'])
@app.route('/items/new', methods=['GET','POST'])
def createItem(category_name = None):
    ''' Create a new item. Can optionally specify category. '''
    
    ''' Restrict access to users not logged in. '''
    if 'username' not in login_session:
        return redirect('/login')
    
    if request.method == 'POST':
        item = Item(name = request.form['name'], description = request.form['description'], category_id = request.form['category_id'], user_id = getUserID(login_session['email']))
        session.add(item)
        session.commit()
        
        return redirect('/items/{}'.format(request.form['name']))
    else:
        ''' Check if request came from a category page. i.e category_name should be the name of that category. '''
        if category_name is not None:
            category = session.query(Category).filter_by(name = category_name).first()
            try:
                if category.id:
                    return render_template('create_item.html', category_name = category.name, categories = getCategories(), user = getUser())
            except AttributeError:
                category_name = None
                return render_template('create_item.html', category_name = category_name, categories = getCategories(), user = getUser())
        else:
            return render_template('create_item.html', category_name = category_name, categories = getCategories(), user = getUser())

@app.route('/logout')
def logout():
    ''' Logs a user out. '''
    
    if 'username' not in login_session:
        return redirect('/login')
    
    if 'gplus_id' in login_session:
        return gdisconnect()
    elif 'facebook_id' in login_session:
        return fbdisconnect()
    
@app.route('/categories/JSON')
def getCategoriesJSON():
    ''' Return Categories in JSON format. '''
    
    categories = session.query(Category).all()
    
    return jsonify( Categories = [category.serialize for category in categories])
    
@app.route('/categories/<string:category_name>/JSON')
def getCategoryJSON(category_name):
    ''' Return information about a category in JSON format. '''
    
    category = session.query(Category).filter_by(name = category_name).first()
    items = session.query(Item).filter_by(category_id = category.id).all()
    
    return jsonify({"Category name" : category.name, "items": [item.serialize for item in items]})

@app.route('/items/JSON')
def getItemsJSOn():
    ''' Return items in JSON format. '''
    
    items = session.query(Item).all()
    
    return jsonify(items = [item.serialize for item in items])
def getUser():
    ''' Return a user list : username and picture if exists. '''
    
    user = {'username' : '', 'picture' : '', 'email' : ''}
    
    if 'username' not in login_session:
        return False
    
    user['username'] = login_session['username']
    user['picture'] = login_session['picture']
    user['email'] = login_session['email']
    
    return user

def getUserID(email):
    ''' Return user id. '''
    
    user = session.query(User).filter_by(email = email).first()
    return user.id

def isOwner(entryUserID):
    ''' Checks if the logged-in user is owner of an entry. '''
    try:
        loggedInUserID = session.query(User).filter_by(email = login_session['email']).first()
        
        if loggedInUserID is entryUserID:
            return True
        else:
            return False
    except : 
        return False

@app.route('/users')
def showUser():
    users = session.query(User).all()
    output = ''
    for user in users:
        output += user.username
        output += str(user.password_hash)
        output += str(user.id)
    return output

def userExists(email):
    ''' Query database and checks if user exists. '''
    
    user = session.query(User).filter_by(email = email).first()
    id = 0
    try:
        id = user.id
        return True
    except AttributeError:
        return False

def createUser(username, email, picture, password):
    ''' Creates a new user, if oAuth user, password will be the access toeken (to prevent empty passwords).'''
    
    user = User(username = username, email = email, picture = picture)
    session.add(user)
    session.commit()
    
    ''' Test user was created. '''
    user = session.query(User).filter_by(email = email).first()
    
    if user.id:
        user.password_hash(password)
        print('success')
    else:
        print('Failed to create user')
    
def getCategories():
    ''' Returns all categories. '''
    
    categories = session.query(Category).all()
    return categories

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
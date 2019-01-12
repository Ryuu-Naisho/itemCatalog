#!/usr/bin/env python3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User

engine = create_engine('sqlite:///itemCatalog.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()

def createUsers():
    '''Create dummy users.'''
    users = []
    users.append({'name' : 'Adam Bob','email' : 'email@ab.com', 'picture' : 'https://taosvhdstorage.blob.core.windows.net/attr/images/member/profile_pictures/no_image.jpg', 'password':'abc123'})
    users.append({'name' : 'Bryan Carl','email' : 'email@bc.com', 'picture' : 'https://taosvhdstorage.blob.core.windows.net/attr/images/member/profile_pictures/no_image.jpg', 'password':'abc123'})
    users.append({'name' : 'Chris Dale','email' : 'email@cd.com', 'picture' : 'https://taosvhdstorage.blob.core.windows.net/attr/images/member/profile_pictures/no_image.jpg', 'password':'abc123'})
    
    ''' Add dummy users to the db.'''
    for user in users :
        session.add(User(username = user['name'], email = user['email'], picture = user['picture']))
        session.commit()
        '''@TODO Figureout how to add password '''

def createCategories():
    ''' Create some categories.'''
    categories = ['sport','outdoor','art']
    
    for category in categories:
        session.add(Category(name = category))
        session.commit()


def createItems():
    ''' Create some items. '''
    items = ['Soccer ball', 'Fishing pole', 'Paint brush']
    descriptions = ['Ball for playing soccer.', 'Pole for fishing.','Brush for painting.']
    
    for i in range(1,len(items)):
        session.add(Item(name = items[i], description = descriptions[i], category_id = i+1, user_id = i+1))
        session.commit()

if __name__ == '__main__':
    createUsers()
    createCategories()
    createItems()
    
    print('Filled the DB.')
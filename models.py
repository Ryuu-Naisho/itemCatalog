#!/usr/bin/env python3

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationships, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))

class User(Base):
    ''' Create User model with auth_token verification. Also returns son output'''
    
    __tablename__ = 'user'
    id = Column(Integer, primary_key = True)
    username = Column(String(32))
    email = Column(String)
    picture = Column(String)
    pasword_hash = Column(String(64))
    
    def hash_password(self, password):      
        self.password_hash = pwd_context.encrypt(password)
        
    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
    
    def generate_auth_token(self, expiration=600):
        serialize = serializer(secret_key, expires_in = expiration)
        return serialize.dumps({'id': self.id})
    
    @staticmethod
    def verify_auth_token(token):
        serialize = Serializer(secret_key)
        
        try:
            data = serialize.loads(token)
        except SignatureExpired:
            return None
        except Badsignature:
            return None
        
        user_id = data['id']
        return user_id
    
    @property
    def serialize(self):
        ''' Return data as json object. '''
        
        return {
            'username' : self.username,
            'picture' : self.picture
            }

class Category(Base):
    ''' Category table. '''
    
    __tablename__ = 'category'
    id = Column(Integer, primary_key = True)
    name = Column(String, index = True)
    
    @property
    def serialize(self):
        ''' Return data as json object '''
        
        return {
            'name' : self.name
            }

class Item(Base):
    ''' Item model. '''
    
    __tablename__ = 'item'
    id = Column(Integer, primary_key = True)
    name = Column(String, index = True)
    description = Column(String)
    category_id = Column(Integer, ForeignKey(Category.id))
    user_id = Column(Integer, ForeignKey(User.id))
    
    @property
    def serialize(self):
        ''' Return data as json object. '''
        
        category = session.query(Category).filter_by(id = self.category_id).firt()
        user = session.query(User).filter_by(id = self.user_id).first()
        
        return {
            'name' : self.name,
            'description' : self.description,
            'category' : category.name,
            'username' : user.username
            }
    
engine = create_engine('sqlite:///itemCatalog.db')

Base.metadata.create_all(engine)
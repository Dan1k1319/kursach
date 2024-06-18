# config.py
import os

basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(instance_path, 'site.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
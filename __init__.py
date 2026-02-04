# This file makes banana_disease_app a Python package
from flask import Flask
from banana_disease_app.flask_api.app import app as flask_app

__all__ = ['flask_app']
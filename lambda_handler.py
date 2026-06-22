import awsgi
from data_aegis_server import app

def handler(event, context):
    return awsgi.response(app, event, context)
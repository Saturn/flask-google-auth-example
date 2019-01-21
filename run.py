
from app import app, db




@app.cli.command(help='Initialise the database.')
def initdb():
    db.drop_all()
    db.create_all()
    print('Done.')

from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import re
from datetime import datetime, timedelta
import logging

app = Flask(__name__)

def setup_logging():
    file_handler = logging.FileHandler('api.log')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - [%(levelname)s]\n%(message)s\n[%(pathname)s %(funcName)s %(lineno)d]\n')
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s\n')
    console_handler.setFormatter(console_formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

setup_logging()

DATABASE_URL = 'sqlite:///users.db'
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(32), unique=True, nullable=False)
    password = Column(String(32), nullable=False)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

attempts = {}
lockout_time = timedelta(minutes=1)

def validate_username(username):
    return 3 <= len(username) <= 32

def validate_password(password):
    return (8 <= len(password) <= 32 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'\d', password))

@app.before_request
def log_request_info():
    logging.info('Request from: %s %s %s', request.remote_addr, request.method, request.path)

@app.route('/create_account', methods=['POST'])
def create_account():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        if not username and not password:
            errorMsg = "Username and password are required."
        elif not username:
            errorMsg = "Username is required."
        else:
            errorMsg = "Password is required."

        logging.error(errorMsg)
        return jsonify({'success': False, 'reason': errorMsg}), 400

    if not validate_username(username):
        logging.error('Invalid username length, username: %s', username)
        return jsonify({'success': False, 'reason': 'Invalid username length.'}), 400

    if not validate_password(password):
        logging.error('Invalid password.')
        return jsonify({'success': False, 'reason': 'Invalid password.'}), 400

    session = Session()
    try:
        if session.query(User).filter_by(username=username).first():
            logging.error('Username already exists: %s', username)
            return jsonify({'success': False, 'reason': 'Username already exists.'}), 400

        new_user = User(username=username, password=password)
        session.add(new_user)
        session.commit()
        logging.info('Account created for username: %s', username)
        return jsonify({'success': True}), 201
    except Exception as e:
        session.rollback()
        logging.error('Error creating account: %s', str(e))
        return jsonify({'success': False, 'reason': str(e)}), 500
    finally:
        session.close()

@app.route('/verify_account', methods=['POST'])
def verify_account():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        if not username and not password:
            errorMsg = "Username and password are required."
        elif not username:
            errorMsg = "Username is required."
        else:
            errorMsg = "Password is required."

        logging.error(errorMsg)
        return jsonify({'success': False, 'reason': errorMsg}), 400

    session = Session()
    try:
        user = session.query(User).filter_by(username=username).first()
        if not user:
            logging.warning('Username does not exist: %s', username)
            return jsonify({'success': False, 'reason': 'Username does not exist.'}), 404

        if username in attempts:
            attempt_info = attempts[username]
            if attempt_info['count'] >= 5:
                if datetime.now() < attempts[username]['time']:
                    logging.warning('Too many failed attempts for username: %s, failed times: %d', username, attempt_info['count'])
                    return jsonify({'success': False, 'reason': 'Too many failed attempts, try again later.'}), 429

        if user.password == password:
            if username in attempts:
                del attempts[username]
            logging.info('Successful login for username: %s', username)
            return jsonify({'success': True}), 200
        else:
            if username not in attempts:
                attempts[username] = {'count': 0, 'time': datetime.now()}
            attempts[username]['count'] += 1
            attempts[username]['time'] = datetime.now() + lockout_time
            logging.warning('Invalid password for username: %s, failed times: %d', username, attempts[username]['count'])
            return jsonify({'success': False, 'reason': 'Invalid password.'}), 401
    except Exception as e:
        logging.error('Error when verifying account: %s', str(e))
        return jsonify({'success': False, 'reason': str(e)}), 500
    finally:
        session.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

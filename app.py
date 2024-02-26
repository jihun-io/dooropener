from flask import Flask, render_template, request, session, flash, abort, redirect, url_for, jsonify
import dooropener
import sqlite3
from threading import Thread
import hashlib
import base64
from datetime import timedelta
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'bing-chat-is-god'
app.permanent_session_lifetime = timedelta(days=365)

door_open_status = False

def dooropen_wrapper():
    global door_open_status
    subprocess.run(['python3', 'controller.py'])
    door_open_status = True

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html', username=session['user_id'])
    else:
        return render_template('index.html')
    
@app.route('/check_door_status')
def check_door_status():
    if 'user_id' in session:
        global door_open_status
        if door_open_status:
            door_open_status = False  # Reset the status
            return jsonify({'status': 'done'})
        else:
            return jsonify({'status': 'pending'})
    else:
        return redirect(url_for('index'))



    

@app.route('/open')
def open():    
    if 'user_id' in session:
        # Create a new thread to run the dooropen function
        thread = Thread(target=dooropen_wrapper)
        thread.start()
        # While the door is opening, render the open.html template with a message
        return render_template('open.html', username=session['user_id'], message="문을 여는 중...")
    else:
        return redirect(url_for('index'))

@app.route('/success', methods=['GET', 'POST'])
def success():    
    if 'user_id' in session:
        # if request.method == 'GET':
        #     tooltip = request.form['tooltip']

        return render_template('success.html', username=session['user_id'])
    else:
        return redirect(url_for('index'))
    


# @app.route('/openjs')
# def openjs():    
#     if 'user_id' in session:
#         dooropener.dooropen()
#         return render_template('result.html', username=session['user_id'], message="님, 환영합니다!")
#     else:
#         return redirect(url_for('index'))



# @app.route('/sign')
# def sign():
#     return render_template('sign.html')

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         salt = os.urandom(32) # 32 bytes long salt

#         hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

#         conn = sqlite3.connect('database.db')
#         c = conn.cursor()

#         c.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
#                   (username, hashed_password, salt))

#         conn.commit()
#         conn.close()

#         return '회원가입이 완료되었습니다!'
#     return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    icon = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT username, password, salt FROM users WHERE username = ?", (username,))
        result = c.fetchone()

        if result is None:
            message = '해당 사용자를\n찾을 수 없습니다.'
            icon = 'error'
        else:
            user_id, db_password, salt = result
            hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

            if db_password == hashed_password:
                session.permanent = True
                session['user_id'] = user_id  # 사용자 아이디를 세션에 저장
                message = '로그인을\n완료했습니다.'
                icon = 'done'
            else:
                message = '해당 사용자를\n찾을 수 없습니다.'
                icon = 'error'

    return render_template('login.html', message=message, icon=icon)

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # 세션에서 사용자 아이디 제거
    return redirect(url_for('index'))

# @app.route('/test')
# def test():
#     if 'user_id' in session:
#         return render_template('success.html', username=session['user_id'])

#     else:
#         return redirect(url_for('index'))

@app.route('/webapp')
def webapp():
    return render_template('webapp.html')




host_addr = "0.0.0.0"
port_num = "4062"

if __name__ == "__main__":

    app.run(host=host_addr, port=port_num)
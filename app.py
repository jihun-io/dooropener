from flask import Flask, render_template, request, session, flash, abort, redirect, url_for, jsonify
import dooropener
import sqlite3
from threading import Thread
from dotenv import load_dotenv
import hashlib
import base64
from itsdangerous import URLSafeTimedSerializer
from time import time
from datetime import datetime
from datetime import timedelta
import os
import subprocess


app = Flask(__name__)

load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
app.permanent_session_lifetime = timedelta(days=365)

startup_time = int(time()) #앱이 시작될 때 시간을 기록

door_open_status = False

def dooropen_wrapper():
    global door_open_status
    subprocess.run(['python3', 'controller.py'])
    door_open_status = True

# 플라스크를 재실행할 때마다 CSS를 새로 불러오는 로직
@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        values['_'] = startup_time
    return url_for(endpoint,**values)

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

            # 문이 열린 후 DB에 기록을 남깁니다.
            conn = sqlite3.connect('database.db')  # DB에 연결합니다.
            c = conn.cursor()
            time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 현재 시간을 가져옵니다.
            c.execute("INSERT INTO unlockLogs (user, time) VALUES (?, ?)", (session['user_id'], time))  # DB에 기록을 남깁니다.
            conn.commit()  # 변경 사항을 저장합니다.
            conn.close()  # DB 연결을 종료합니다.
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

@app.route('/settings')
def settings():
    if 'user_id' in session:
        return render_template('settings.html', username=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/dev')
def dev():
    if 'user_id' in session:
        return render_template('dev.html', username=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/shortcuts')
def shortcuts():
    if 'user_id' in session:
        return render_template('shortcuts.html', username=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/shortcuts/token')
def token():
    if 'user_id' in session:
        return render_template('token.html', username=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/shortcuts/token/generate')
def warn_generate_token():
    if 'user_id' in session:
        return render_template('generate.html')
    else:
        return redirect(url_for('index'))
    
@app.route('/generate', methods=['GET', 'POST'])
def generate_token():
    if 'user_id' in session:
        if request.method == 'POST':
            qGenerate = request.form['qGenerate']
            if qGenerate == "1":
                s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
                token = s.dumps(session['user_id'])  # 세션의 user_id를 이용해 토큰을 생성합니다.

                conn = sqlite3.connect('database.db')  # 데이터베이스에 연결합니다.
                c = conn.cursor()
                c.execute("UPDATE users SET token = ? WHERE username = ?", (token, session['user_id']))  # users 테이블의 token 필드를 업데이트합니다.
                conn.commit()
                conn.close()

                domain = request.host
                scLink = domain + "/sc?t=" + token
                return render_template('generate_result.html', token=token, scLink=scLink)
            else:
                return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/shortcuts/token/revoke')
def warn_revoke_token():
    if 'user_id' in session:
        return render_template('revoke.html')
    else:
        return redirect(url_for('index'))

@app.route('/revoke', methods=['GET', 'POST'])
def revoke_token():
    if 'user_id' in session:
        if request.method == 'POST':
            qRevoke = request.form['qRevoke']
            if qRevoke == "1":
                conn = sqlite3.connect('database.db')  # 데이터베이스에 연결합니다.
                c = conn.cursor()

                c.execute("UPDATE users SET token = NULL WHERE username = ?", (session['user_id'],))

                conn.commit()
                conn.close()

                message = '기존 토큰이 정상적으로\n파기되었습니다.'
                return render_template('revoke_complete.html', message=message)
            else:
                return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/shortcuts/add')
def addshortcuts():
    if 'user_id' in session:
        return render_template('add.html', username=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@app.route('/sc', methods=['GET'])
def openwithapi():
    usertoken = request.args.get('t')

    if usertoken is not None:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE token=?", (usertoken,))
        data = c.fetchone()

        if data is not None:
            username = data[0]  # 'username' 필드의 위치에 따라 이 값이 달라질 수 있습니다.
            dooropener()
            return render_template('openwithapi.html', message=f"{username} 님, 환영합니다!")
        else:
            return render_template('openwithapi.html', message="오류가 발생했습니다.")
    else:
        return render_template('openwithapi.html', message="토큰이 제공되지 않았습니다.")



host_addr = "0.0.0.0"
port_num = "4062"

if __name__ == "__main__":

    app.run(host=host_addr, port=port_num)
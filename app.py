from flask import Flask, render_template, request, session, flash, abort, redirect, url_for, jsonify
# import asyncio
# from celery import Celery
# import redis
# import dooropener # 웬만하면 불러오지 마시오
import sqlite3
from threading import Thread
from dotenv import load_dotenv
import random
import string
import hashlib
import secrets
import base64
from itsdangerous import URLSafeTimedSerializer
from time import time
from datetime import datetime
from datetime import timedelta
import os
import subprocess
from pyapns_client import APNSClient, TokenBasedAuth, IOSPayloadAlert, IOSPayload, IOSNotification, APNSDeviceException, APNSServerException, APNSProgrammingException, UnregisteredException
# from pyapns import configure, provision, notify


app = Flask(__name__)


load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
app.permanent_session_lifetime = timedelta(days=365)

shortcut_address = "https://www.icloud.com/shortcuts/fe1e91c422474cfcbbd53c4c1769fc97"

# 개발자 모드 추가
dev_path = 'dev.txt'
dev_mode = os.path.isfile(dev_path)

# 푸시 알림 키 설정
app_auth_key_path = os.getenv('auth_key_path')
app_auth_key_id = os.getenv('auth_key_id')
app_team_id= os.getenv('team_id')

# 문 열어주는 코드 실행하기
door_open_status = False
def dooropen_wrapper():
    global door_open_status
    if dev_mode == False:
        subprocess.run(['python3', 'controller.py'])
    door_open_status = True

# 초대 코드 생성기
def invite_code(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

# 푸시 알림 전송 함수
def push(ptitle, psubtitle, pbody, sender, dev):
    if dev_mode == False:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        if dev and sender == 0:
            c.execute("SELECT apnstokens.token FROM apnstokens JOIN users ON apnstokens.email = users.email WHERE users.isAdmin = 1")
        elif dev and sender != 0:
            c.execute("SELECT apnstokens.token FROM apnstokens JOIN users ON apnstokens.email = users.email WHERE users.isAdmin = 1 AND apnstokens.email != ?", (sender,))
        elif not dev and sender == 0:
            c.execute("SELECT token FROM apnstokens")
        else:  # not dev and sender != 0
            c.execute("SELECT token FROM apnstokens WHERE email != ?", (sender,))

        results = c.fetchall()
        device_tokens = [row[0] for row in results]  # Extract the token from each row

        # alert = IOSPayloadAlert(title=ptitle, subtitle=psubtitle, body=pbody)
        alert = IOSPayloadAlert(title=psubtitle, body=pbody)
        payload = IOSPayload(alert=alert, sound='default')
        notification = IOSNotification(payload=payload, topic='io.jihun.DoorOpener')
        
        messages = []
        with APNSClient(
            mode=APNSClient.MODE_PROD,
            authentificator=TokenBasedAuth(
                auth_key_path=app_auth_key_path,
                auth_key_id=app_auth_key_id,
                team_id=app_team_id
            ),
            root_cert_path = None,
        ) as client:
            for device_token in device_tokens:
                try:
                    client.push(notification=notification, device_token=device_token)
                except UnregisteredException as e:
                    messages.append(f'device is unregistered, compare timestamp {e.timestamp_datetime} and remove from db')
                except APNSDeviceException:
                    messages.append('flag the device as potentially invalid and remove from db after a few tries')
                except APNSServerException:
                    messages.append('try again later')
                except APNSProgrammingException:
                    messages.append('check your code and try again later')
                else:
                    messages.append('everything is ok')
        return messages
    else:
        messages = 'everything is ok'
        return messages

def log_write(username, path):
    # 문이 열린 후 DB에 기록을 남깁니다.
    conn = sqlite3.connect('database.db')  # DB에 연결합니다.
    c = conn.cursor()
    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 현재 시간을 가져옵니다.
    if path != None:
        c.execute("INSERT INTO unlockLogs (user, time, isToken) VALUES (?, ?, ?)", (username, time, path))  # DB에 기록을 남깁니다.
    else:
        c.execute("INSERT INTO unlockLogs (user, time) VALUES (?, ?)", (username, time))  # DB에 기록을 남깁니다.

    conn.commit()  # 변경 사항을 저장합니다.
    conn.close()  # DB 연결을 종료합니다.
    pass


# 플라스크를 재실행할 때마다 CSS를 새로 불러오는 로직
startup_time = int(time()) #앱이 시작될 때 시간을 기록
@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

def dated_url_for(endpoint, **values):
    if dev_mode == True:
        if endpoint == 'static':
            values['_'] = int(time())
    else:
        if endpoint == 'static':
            values['_'] = startup_time
    return url_for(endpoint,**values)



@app.route('/')
def index():
    if 'user_id' in session:
        if dev_mode == True:
            return render_template('index.html', username=session['user_username'], devWarn="개발 - ")
        else:
            return render_template('index.html', username=session['user_username'])
    else:
        return render_template('index.html')
    
@app.route('/check_door_status')
def check_door_status():
    if 'user_id' in session:
        global door_open_status
        if door_open_status:
            door_open_status = False  # Reset the status

            thread_log_write = Thread(target=log_write, args=(session['user_username'], None))
            thread_log_write.start()

            push_message = session['user_username'] + " 님이 잠금을 해제했습니다."
            thread_push = Thread(target=push, args=("DoorOpener", "잠금 해제됨", push_message, session['user_id'], False))
            thread_push.start()

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
        return render_template('open.html', username=session['user_username'], message="문을 여는 중...")
    else:
        return redirect(url_for('index'))
    
@app.route('/openwithapp')
def openwithapp():    
    if 'user_id' in session:
        subprocess.run(['python3', 'controller.py'])

        thread_log_write = Thread(target=log_write, args=(session['user_username'], 2))
        thread_log_write.start()

        push_message = session['user_username'] + " 님이 잠금을 해제했습니다."

        thread_push = Thread(target=push, args=("DoorOpener", "잠금 해제", push_message, session['user_id'], False))
        thread_push.start()

        return render_template('openwithapp.html', message="문을 열었습니다.")
    else:
        return redirect(url_for('index'))
    
@app.route('/openwithappjson')
def openwithappjson():    
    if 'user_id' in session:
        subprocess.run(['python3', 'controller.py'])
        # 문이 열린 후 DB에 기록을 남깁니다.

        thread_log_write = Thread(target=log_write, args=(session['user_username'], 2))
        thread_log_write.start()

        push_message = session['user_username'] + " 님이 잠금을 해제했습니다."

        thread_push = Thread(target=push, args=("DoorOpener", "잠금 해제", push_message, session['user_id'], False))
        thread_push.start()
        result = "Success"

        return jsonify(result=result)
    else:
        return redirect(url_for('index'))
    
@app.route('/openwithappjsonwithoutnotification')
def openwithappjsonwithoutnotification():    
    if 'user_id' in session:
        subprocess.run(['python3', 'controller.py'])
        # 문이 열린 후 DB에 기록을 남깁니다.

        thread_log_write = Thread(target=log_write, args=(session['user_username'], 2))
        thread_log_write.start()

        push_message = session['user_username'] + " 님이 잠금을 해제했습니다."

        # thread_push = Thread(target=push, args=("DoorOpener", "잠금 해제", push_message, session['user_id'], False))
        # thread_push.start()
        result = "Success"

        return jsonify(result=result)
    else:
        return redirect(url_for('index'))


@app.route('/openwithapptest')
def openwithapptest():    
    if 'user_id' in session:
        # subprocess.run(['python3', 'controller.py'])
        # 문이 열린 후 DB에 기록을 남깁니다.
        # conn = sqlite3.connect('database.db')  # DB에 연결합니다.
        # c = conn.cursor()
        # time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 현재 시간을 가져옵니다.
        # c.execute("INSERT INTO unlockLogs (user, time) VALUES (?, ?)", (session['user_username'], time))  # DB에 기록을 남깁니다.
        # conn.commit()  # 변경 사항을 저장합니다.
        # conn.close()  # DB 연결을 종료합니다.
        push_message = "테스트: " + session['user_username'] + " 님이 잠금을 해제했습니다."
        thread_push = Thread(target=push, args=("DoorOpener", "잠금 해제 테스트", push_message, session['user_id'], True))
        thread_push.start()

        return render_template('openwithapp.html', message="문을 열었습니다.")
    else:
        return redirect(url_for('index'))
    
@app.route('/openwithapptestjson')
def openwithapptestjson():    
    if 'user_id' in session:
        # subprocess.run(['python3', 'controller.py'])
        # 문이 열린 후 DB에 기록을 남깁니다.
        # conn = sqlite3.connect('database.db')  # DB에 연결합니다.
        # c = conn.cursor()
        # time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 현재 시간을 가져옵니다.
        # c.execute("INSERT INTO unlockLogs (user, time, istoken) VALUES (?, ?, ?)", (session['user_username'], time, 2))  # DB에 기록을 남깁니다.
        # conn.commit()  # 변경 사항을 저장합니다.
        # conn.close()  # DB 연결을 종료합니다.

        push_message = session['user_username'] + " 님이 잠금을 해제했습니다."
        thread_push = Thread(target=push, args=("DoorOpener", "잠금 해제 테스트", push_message, session['user_id'], True))
        thread_push.start()

        result = "Success"

        return jsonify(result=result)
    else:
        return redirect(url_for('index'))

@app.route('/useragenttest')
def useragenttest():   
    return jsonify(message=request.user_agent.string)


@app.route('/success', methods=['GET', 'POST'])
def success():    
    if 'user_id' in session:
        # if request.method == 'GET':
        #     tooltip = request.form['tooltip']

        return render_template('success.html', username=session['user_username'])
    else:
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    icon = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT username, password, salt FROM users WHERE email = ?", (email,))
        result = c.fetchone()

        if result is None:
            message = '해당 사용자를\n찾을 수 없습니다.'
            icon = 'error'
        else:
            username, db_password, salt = result
            hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

            if db_password == hashed_password:
                session.permanent = True
                session['user_username'] = username  
                session['user_id'] = email # 사용자 아이디를 세션에 저장
                message = '로그인을\n완료했습니다.'
                icon = 'done'
            else:
                message = '해당 사용자를\n찾을 수 없습니다.'
                icon = 'error'

    return render_template('login.html', message=message, icon=icon)

@app.route('/loginwithapp', methods=['POST'])
def loginwithapp():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("SELECT username, password, salt FROM users WHERE email = ?", (email,))
    result = c.fetchone()

    if result is None:
        return jsonify(result = 'Failed')
    else:
        username, db_password, salt = result
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

        if db_password == hashed_password:
            session.permanent = True
            session['user_username'] = username  
            session['user_id'] = email # 사용자 아이디를 세션에 저장
            c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
            result = c.fetchone()
            isAdmin = result[0]
            return jsonify(result='Success', username=username, email=email, isAdmin=isAdmin)
        else:
            return jsonify(result = 'Failed')

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # 세션에서 사용자 아이디 제거
    return redirect(url_for('index'))

@app.route('/webapp')
def webapp():
    return render_template('webapp.html')

@app.route('/settings')
def settings():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]
        return render_template('settings.html', username=session['user_username'], isAdmin=isAdmin)
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/user')
def user():
    if 'user_id' in session:
        return render_template('user.html', username=session['user_username'], email=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/user/modify')
def modifyInfo():
    if 'user_id' in session:
        return render_template('modifyuserinfo.html', username=session['user_username'], email=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/user/modify/request', methods=['GET', 'POST'])
def modifyInfoRequest():
    if 'user_id' in session:
        if request.method == 'POST':
            new_username = request.form['username']
            new_email = request.form['email']
            user_id = session['user_id']

            conn = sqlite3.connect('database.db')
            c = conn.cursor()

            c.execute("UPDATE users SET username = ?, email = ? WHERE email = ?", (new_username, new_email, user_id))
            conn.commit()
            conn.close()

            session['user_username'] = new_username
            session['user_id'] = new_email

            return redirect(url_for('user'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/user/password')
def modifyPW():
    if 'user_id' in session:
        return render_template('modifyuserpw.html', username=session['user_username'])
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/user/password/request', methods=['GET', 'POST'])
def modifyPWRequest():
    if 'user_id' in session:
        if request.method == 'POST':
            new_password = request.form['password']
            user_id = session['user_id']

            conn = sqlite3.connect('database.db')
            c = conn.cursor()

            salt = os.urandom(32) # 32 bytes long salt
            hashed_password = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), salt, 100000)

            c.execute("UPDATE users SET password = ?, salt = ? WHERE email = ?", (hashed_password, salt, user_id))
            conn.commit()
            conn.close()
            session.pop('user_id', None)

            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))
    

@app.route('/settings/dev')
def dev():
    if 'user_id' in session:
        useragent = request.user_agent.string
        return render_template('dev.html', username=session['user_username'], useragent=useragent)
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/shortcuts')
def shortcuts():
    if 'user_id' in session:
        return render_template('shortcuts.html', username=session['user_username'], shortcut_address=shortcut_address)
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/shortcuts/token')
def token():
    if 'user_id' in session:
        return render_template('token.html', username=session['user_username'])
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
                c.execute("UPDATE users SET token = ? WHERE email = ?", (token, session['user_id']))  # users 테이블의 token 필드를 업데이트합니다.
                conn.commit()
                conn.close()

                domain = request.host_url
                scLink = domain + "sc?t=" + token
                return render_template('generate_result.html', token=token, scLink=scLink, shortcut_address=shortcut_address)
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

                c.execute("UPDATE users SET token = NULL WHERE email = ?", (session['user_id'],))

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
        return render_template('add.html', username=session['user_username'])
    else:
        return redirect(url_for('index'))
    
@app.route('/sc', methods=['GET'])
def openwithapi():
    usertoken = request.args.get('t')
    useragent = request.user_agent.string
    if useragent.startswith("BackgroundShortcutRunner"):
        if usertoken is not None:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE token=?", (usertoken,))
            data = c.fetchone()

            if data is not None:
                username = data[1]  # 'username' 필드의 위치에 따라 이 값이 달라질 수 있습니다.
                if dev_mode == False:
                    subprocess.run(['python3', 'controller.py'])
                else:
                    pass
                # 문이 열린 후 DB에 기록을 남깁니다.
                log_write(session['user_username'], 1)

                push_message = username + " 님이 잠금을 해제했습니다."
                thread_push = Thread(target=push, args=("DoorOpener", "잠금 해제됨", push_message, "", False))
                thread_push.start()

                return render_template('openwithapi.html', message=f"{username} 님, 환영합니다!")
            else:
                return render_template('openwithapi.html', message="오류가 발생했습니다.")
        else:
            return render_template('openwithapi.html', message="토큰이 제공되지 않았습니다.")
    else:
        return redirect(url_for('index'))

@app.route('/settings/logs')
def logs():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM unlockLogs ORDER BY time DESC")
        logs = c.fetchall()

        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]

        conn.close()

        return render_template('logs.html',isAdmin=isAdmin, logs=logs)
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/logs/reset')
def logs_reset():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]

        if isAdmin == 1:
            c.execute("DELETE FROM unlockLogs")
            conn.commit()

            c.execute("SELECT * FROM unlockLogs ORDER BY time DESC")
            conn.close()
            return redirect(url_for('logs'))
        else:
            return redirect(url_for('logs'))
    else:
        return redirect(url_for('index'))


@app.route('/settings/invite')
def invite_list():
    if 'user_id' in session:
        current_time = int(datetime.now().timestamp())
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("DELETE FROM inviteCodes WHERE expDate < ?", (current_time,))
        conn.commit()

        c.execute("SELECT * FROM inviteCodes WHERE invitor = ?", (session['user_id'],))
        
        invite_codes = c.fetchall()
        conn.close()

        return render_template('invite.html', invite_codes=invite_codes)
    else:
        return redirect(url_for('index'))
    
@app.route('/invitecode')
def invite_link_gen():
    if 'user_id' in session:
        code = invite_code(12)
        expDate = int((datetime.now() + timedelta(minutes=15)).timestamp())

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO inviteCodes (invitor, code, expDate) VALUES (?, ?, ?)", (session['user_id'], code, expDate))
        conn.commit()

        return redirect(url_for('invite_list'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/invite/info', methods=['GET'])
def invite_link_info():
    if 'user_id' in session:
        code = request.args.get('code')

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM inviteCodes WHERE code=?", (code,))
        data = c.fetchone()

        if data is not None:
            timestamp = data[2]
            dt_object = datetime.fromtimestamp(timestamp)
            formatted_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            return render_template('codeinfo.html', data=data, time_convert=formatted_time)
        else:
            return redirect(url_for('invite_list'))
        
    else:
        return redirect(url_for('index'))

@app.route('/settings/invite/info/del', methods=['GET'])
def invite_link_del():
    if 'user_id' in session:
        code = request.args.get('code')

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("DELETE FROM inviteCodes WHERE code=?", (code,))
        conn.commit()

        return redirect(url_for('invite_list'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/admin')
def admin():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]
        
        if isAdmin == 1:
            return render_template('admin.html')
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/admin/userslist', methods=['GET'])
def users_list():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]
        
        if isAdmin == 1:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("SELECT username, email, invitorUsername, invitorEmail, isAdmin, serial FROM users ORDER BY serial")
            lists = c.fetchall()
            conn.close()
            return render_template('userslist.html', username=session['user_id'], lists=lists)
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/admin/userslist/permission', methods=['GET'])
def users_lists_permission():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]
        
        if isAdmin == 1:
            email = request.args.get('id')

            if session['user_id'] == email:
                return redirect(url_for('users_list'))
            else:
                c.execute("SELECT isAdmin FROM users WHERE email = ?", (email,))
                result = c.fetchone()
                theyAdmin = result[0]

                c.execute("SELECT serial FROM users WHERE email = ?", (email,))
                result = c.fetchone()
                theySerial = result[0]

                if theyAdmin == 1:
                    c.execute("UPDATE users SET isAdmin = Null WHERE email = ?", (email,))
                    conn.commit()
                    conn.close()
                else:
                    c.execute("UPDATE users SET isAdmin = 1 WHERE email = ?", (email,))
                    conn.commit()
                    conn.close()
                return redirect(url_for('users_list'))
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/admin/userlist/del', methods=['GET'])
def users_lists_delete():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]
        
        if isAdmin == 1:
            email = request.args.get('id')
            if session['user_id'] == email:
                return redirect(url_for('users_list'))
            else:
                c.execute("SELECT serial FROM users WHERE email = ?", (email,))
                result = c.fetchone()
                theySerial = result[0]
                c.execute("DELETE FROM users WHERE email = ?", (email,))
                conn.commit()
                conn.close()
                return redirect(url_for('users_list'))
            
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))
    
@app.route('/settings/user/del', methods=['GET'])
def users_delete():
    if 'user_id' in session:
        email = request.args.get('id')
        if session['user_id'] == email:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE email = ?", (email,))
            conn.commit()
            conn.close()
            session.pop('user_id', None)
            return redirect(url_for('index'))
        else: 
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

    
@app.route('/join', methods=['GET'])
def join_invite():
    session.pop('user_id', None)

    invite_code = request.args.get('code')
    
    current_time = int(datetime.now().timestamp())
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM inviteCodes WHERE expDate < ?", (current_time,))
    conn.commit()

    c.execute("SELECT * FROM inviteCodes WHERE code = ?", (invite_code,))
    result = c.fetchone()

    if result is None:
        message = "초대 링크가 만료되었거나 올바르지 않습니다."
        icon = "error"
        return render_template('login.html', message=message, icon=icon)
    else:
        return render_template('sign.html', code=invite_code)
    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    invite_code = request.args.get('code')

    current_time = int(datetime.now().timestamp())
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM inviteCodes WHERE expDate < ?", (current_time,))
    conn.commit()

    c.execute("SELECT * FROM inviteCodes WHERE code = ?", (invite_code,))
    result = c.fetchone()

    invitorEmail = result[0]

    if result is None:
        message = "초대 링크가 만료되었거나 올바르지 않습니다."
        icon = "error"
        return render_template('login.html', message=message, icon=icon)
    else:
        if request.method == 'POST':
            conn = sqlite3.connect('database.db')
            c = conn.cursor()

            username = request.form['realname']
            password = request.form['password']
            email = request.form['email']

            c.execute("SELECT email FROM users WHERE email = ?", (email,))
            result = c.fetchone()

            if result is None:
                c.execute("SELECT username FROM users WHERE email = ?", (invitorEmail,))
                result = c.fetchone()
                invitorUsername = result[0]

                salt = os.urandom(32) # 32 bytes long salt
                hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
                c.execute("INSERT INTO users (email, username, password, salt, invitorEmail, invitorUsername) VALUES (?, ?, ?, ?, ?, ?)",
                        (email, username, hashed_password, salt, invitorEmail, invitorUsername))

                c.execute("DELETE FROM inviteCodes WHERE code = ?", (invite_code,))
                conn.commit()
                conn.close()

                message = "회원가입이 완료되었습니다!"
                icon = "check_circle"
                return render_template('login.html', message=message, icon=icon)
            else:
                message = "다른 이메일을 사용해주세요."
                icon = "error"
                return render_template('sign.html', message=message, username=username, code=invite_code)


@app.route('/applewatch/generate')
def generate_applewatch_token():
    if 'user_id' in session:
        current_time = int(datetime.now().timestamp())

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("DELETE FROM awtokens WHERE expdate < ?", (current_time,))
        conn.commit()

        email = session['user_id']
        username = session['user_username']

        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token = s.dumps(session['user_id'])  # 세션의 user_id를 이용해 토큰을 생성합니다.
        salt = app.secret_key
        salt = salt.encode("utf-8")
        hashed_token = hashlib.pbkdf2_hmac('sha256', token.encode('utf-8'), salt, 100000)

        expDate = int((datetime.now() + timedelta(minutes=15)).timestamp())

        c.execute("INSERT INTO awtokens (email, username, token, salt, expDate) VALUES(?, ?, ?, ?, ?)", (email, username, hashed_token, salt, expDate))

        conn.commit()
        conn.close()

        domain = request.host_url
        scLink = domain + "applewatch/login?t=" + token
        return jsonify(link=scLink)
    else:
        return redirect(url_for('index'))

@app.route('/applewatch/login', methods=['GET'])
def login_applewatch_token():
    current_time = int(datetime.now().timestamp())

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("DELETE FROM awtokens WHERE expdate < ?", (current_time,))
    conn.commit()

    token = request.args.get('t')
    salt = app.secret_key
    salt = salt.encode("utf-8")
    if token is not None:
        hashed_token = hashlib.pbkdf2_hmac('sha256', token.encode('utf-8'), salt, 100000)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT email, username FROM awtokens WHERE token = ?", (hashed_token,))
        result = c.fetchone()
        c.execute("DELETE FROM awtokens WHERE token = ?", (hashed_token,))
        conn.commit()

        if result is None:
            message = 'Token Not Available'
            return jsonify(message=message)
        else:
            email, username = result

            session.permanent = True
            session['user_username'] = username  
            session['user_id'] = email # 사용자 아이디를 세션에 저장
            message = "Success"
            return jsonify(message=message, email=email, username=username)
    else:
        return redirect(url_for('index'))
    

@app.route('/apnstokenget', methods=['GET', 'POST'])
def apns_token_get():
    if request.method == 'POST':
        email = request.form['email']
        token = request.form['token']
        if token is not None:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            
            # Check the number of tokens for the user
            c.execute("SELECT COUNT(*) FROM apnstokens WHERE email = ?", (email,))
            count = c.fetchone()[0]
            
            # # If the user already has 4 tokens, delete the oldest one
            # if count >= 4:
            #     c.execute("DELETE FROM apnstokens WHERE email = ? ORDER BY timestamp_column LIMIT 1", (email,))
            
            # Insert the new token, ignore if it already exists
            c.execute("INSERT OR IGNORE INTO apnstokens (email, token) VALUES(?, ?)", (email, token))
            
            conn.commit()
            conn.close()
            return 'Token Registration Completed', 200
        else:
            return 'No token provided!', 400
    else:
        return 'Invalid request method!', 405
    
@app.route('/apnstokenremove', methods=['GET', 'POST'])
def apns_token_remove():
    if request.method == 'POST':
        token = request.form['token']
        if token is not None:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            
            # Check the number of tokens for the user
            c.execute("DELETE FROM apnstokens WHERE token = ?", (token,))            
            conn.commit()
            conn.close()
            return 'Token Remove Completed', 200
        else:
            return 'No token provided!', 400
    else:
        return 'Invalid request method!', 405




@app.route('/pushtest')
def pushtest():
    if 'user_id' in session:
        thread_push = Thread(target=push, args=push("DoorOpener", "알림 테스트", "푸시 알림 테스트입니다.", 0, True))
        thread_push.start()

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT email, token FROM apnstokens")
        results = c.fetchall()
        return results
    else:
        return redirect(url_for('index'))

@app.route('/settings/user/info')
def user_info_json():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]
        return jsonify(email=session['user_id'], username=session['user_username'], isAdmin=isAdmin)
    else:
        return jsonify(message="Failed")

host_addr = "0.0.0.0"
port_num = "4062"

if __name__ == "__main__":
    if dev_mode == True:
        print("개발자 모드입니다.")
        app.run(host=host_addr, port=port_num, debug=True)
    else:
        app.run(host=host_addr, port=port_num)
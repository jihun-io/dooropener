from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify
import sqlite3
from dotenv import load_dotenv
import random
import string
import hashlib
from itsdangerous import URLSafeTimedSerializer
from time import time
from datetime import datetime
from datetime import timedelta
import os
from pyapns_client import APNSClient, TokenBasedAuth, IOSPayloadAlert, IOSPayload, IOSNotification, APNSDeviceException, APNSServerException, APNSProgrammingException, UnregisteredException

settings = Blueprint("settings", __name__, template_folder="templates")

shortcut_address = "https://www.icloud.com/shortcuts/fe1e91c422474cfcbbd53c4c1769fc97"

dev_path = 'dev.txt'
dev_mode = os.path.isfile(dev_path)
settings.secret_key = os.getenv('SECRET_KEY')
settings.permanent_session_lifetime = timedelta(days=365)

# 초대 코드 생성기
def invite_code(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string


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


@settings.route('/settings')
def settings_main():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT isAdmin FROM users WHERE email = ?", (session['user_id'],))
        result = c.fetchone()
        isAdmin = result[0]
        return render_template('settings.html', username=session['user_username'], isAdmin=isAdmin)
    else:
        return redirect(url_for('index'))
    
@settings.route('/settings/user')
def user():
    if 'user_id' in session:
        return render_template('user.html', username=session['user_username'], email=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@settings.route('/settings/user/modify')
def modifyInfo():
    if 'user_id' in session:
        return render_template('modifyuserinfo.html', username=session['user_username'], email=session['user_id'])
    else:
        return redirect(url_for('index'))
    
@settings.route('/settings/user/modify/request', methods=['GET', 'POST'])
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
    
@settings.route('/settings/user/password')
def modifyPW():
    if 'user_id' in session:
        return render_template('modifyuserpw.html', username=session['user_username'])
    else:
        return redirect(url_for('index'))
    
@settings.route('/settings/user/password/request', methods=['GET', 'POST'])
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
    

@settings.route('/settings/dev')
def dev():
    if 'user_id' in session:
        useragent = request.user_agent.string
        return render_template('dev.html', username=session['user_username'], useragent=useragent)
    else:
        return redirect(url_for('index'))
    
@settings.route('/settings/shortcuts')
def shortcuts():
    if 'user_id' in session:
        return render_template('shortcuts.html', username=session['user_username'], shortcut_address=shortcut_address)
    else:
        return redirect(url_for('index'))
    
@settings.route('/settings/shortcuts/token')
def token():
    if 'user_id' in session:
        return render_template('token.html', username=session['user_username'])
    else:
        return redirect(url_for('index'))
    
@settings.route('/settings/shortcuts/token/generate')
def warn_generate_token():
    if 'user_id' in session:
        return render_template('generate.html')
    else:
        return redirect(url_for('index'))
    
@settings.route('/generate', methods=['GET', 'POST'])
def generate_token():
    if 'user_id' in session:
        if request.method == 'POST':
            qGenerate = request.form['qGenerate']
            if qGenerate == "1":
                s = URLSafeTimedSerializer(settings.config['SECRET_KEY'])
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

    
@settings.route('/settings/shortcuts/token/revoke')
def warn_revoke_token():
    if 'user_id' in session:
        return render_template('revoke.html')
    else:
        return redirect(url_for('index'))

@settings.route('/revoke', methods=['GET', 'POST'])
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
    
@settings.route('/settings/shortcuts/add')
def addshortcuts():
    if 'user_id' in session:
        return render_template('add.html', username=session['user_username'])
    else:
        return redirect(url_for('index'))
    

@settings.route('/settings/logs')
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
    
@settings.route('/settings/logs/reset')
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


@settings.route('/settings/invite')
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
    
@settings.route('/invitecode')
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
    
@settings.route('/settings/invite/info', methods=['GET'])
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

@settings.route('/settings/invite/info/del', methods=['GET'])
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
    
@settings.route('/settings/admin')
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
    
@settings.route('/settings/admin/userslist', methods=['GET'])
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
    
@settings.route('/settings/admin/userslist/permission', methods=['GET'])
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
    
@settings.route('/settings/admin/userlist/del', methods=['GET'])
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
    
@settings.route('/settings/user/del', methods=['GET'])
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

@settings.route('/applewatch/generate')
def generate_applewatch_token():
    if 'user_id' in session:
        current_time = int(datetime.now().timestamp())

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("DELETE FROM awtokens WHERE expdate < ?", (current_time,))
        conn.commit()

        email = session['user_id']
        username = session['user_username']

        s = URLSafeTimedSerializer(settings.config['SECRET_KEY'])
        token = s.dumps(session['user_id'])  # 세션의 user_id를 이용해 토큰을 생성합니다.
        salt = settings.secret_key
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

@settings.route('/applewatch/login', methods=['GET'])
def login_applewatch_token():
    current_time = int(datetime.now().timestamp())

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("DELETE FROM awtokens WHERE expdate < ?", (current_time,))
    conn.commit()

    token = request.args.get('t')
    salt = settings.secret_key
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
    

@settings.route('/settings/user/info')
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
    
@settings.route('/apnstokenget', methods=['GET', 'POST'])
def apns_token_get():
    if request.method == 'POST':
        email = request.form['email']
        token = request.form['token']
        if token is not None:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            
            # # Check the number of tokens for the user
            # c.execute("SELECT COUNT(*) FROM apnstokens WHERE email = ?", (email,))
            # count = c.fetchone()[0]
            
            # # # If the user already has 4 tokens, delete the oldest one
            # # if count >= 4:
            # #     c.execute("DELETE FROM apnstokens WHERE email = ? ORDER BY timestamp_column LIMIT 1", (email,))
            
            # # Insert the new token, ignore if it already exists
            c.execute("INSERT OR IGNORE INTO apnstokens (email, token) VALUES(?, ?)", (email, token))
            
            conn.commit()
            conn.close()
            return 'Token Registration Completed', 200
        else:
            return 'No token provided!', 400
    else:
        return 'Invalid request method!', 405
    
@settings.route('/apnstokenremove', methods=['GET', 'POST'])
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
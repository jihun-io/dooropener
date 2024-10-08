from flask import Flask, Blueprint, render_template, request, session, flash, abort, redirect, url_for, jsonify

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

account = Blueprint("open", __name__, template_folder="templates")

# 관리자 체크 함수
def adminCheck(userID):
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute("SELECT isAdmin FROM users WHERE email = ?", (userID,))
        result = c.fetchone()
        isAdmin = result[0]
        return isAdmin


@account.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    icon = ''
    if request.method == 'POST':
        isOOBENext = False
        
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
                
                if os.path.isfile("OOBEPending"):
                    isOOBENext = True
                else:
                    isOOBENext = False
                    
                message = '로그인을\n완료했습니다.'
                icon = 'done'
            else:
                message = '해당 사용자를\n찾을 수 없습니다.'
                icon = 'error'

    return render_template('login.html', message=message, icon=icon, isOOBENext=isOOBENext)

@account.route('/loginwithapp', methods=['POST'])
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

@account.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_username', None)
    session.pop('temp_keyname', None)
    session.pop('temp_keyvalue', None)
    session.pop('temp_keyexp', None)
    return redirect(url_for('index'))

@account.route('/join', methods=['GET'])
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
    
@account.route('/signup', methods=['GET', 'POST'])
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

                message = "사용자 등록이 완료되었습니다!"
                icon = "check_circle"
                return render_template('login.html', message=message, icon=icon)
            else:
                message = "다른 이메일을 사용하십시오."
                icon = "error"
                return render_template('sign.html', message=message, username=username, code=invite_code)


@account.route('/tempkey')            
def temp_key_login():
    session.pop('user_id', None)
    session.pop('tempkey_id', None)

    return render_template('tempkey_login.html')


@account.route('/tempkey/get', methods=['POST'])
def temp_key_get():
    session.pop('user_id', None)
    session.pop('tempkey_id', None)
    
    message = ''
    icon = ''
    if request.method == 'POST':
        keyname = request.form['username']
        authnum = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        c.execute("SELECT keyname, authnum, startDate, endDate, isLogin FROM tempKey WHERE authnum = ?", (authnum,))
        result = c.fetchone()
        
        if result is None:
            message = '임시 키를\n찾을 수 없습니다.'
            icon = 'error'
        else:
            print(result)
            keynameDB, authnum, startDateDB, endDateDB, isLogin = result
            
            now = datetime.now()
            startDate = datetime.strptime(startDateDB, "%Y-%m-%d %H:%M:%S")
            endDate = datetime.strptime(endDateDB, "%Y-%m-%d %H:%M:%S")            
            
            
            if isLogin == 1:
                message = '이미 발급받은\n임시 키입니다.'
                icon = 'error'
            elif keyname != keynameDB:
                message = '임시 키를\n찾을 수 없습니다.'
                icon = 'error'
            elif startDate > now:
                message = '임시 키를\n찾을 수 없습니다.'
                icon = 'error'
            elif endDate < now:
                message = '임시 키가\만료되었습니다.'
                icon = 'error'
            elif keyname == keynameDB:
                session.permanent = True
                
                session['temp_keyname'] = keynameDB
                session['temp_keyvalue'] = authnum
                session['temp_keyexp'] = endDate
                message = '임시 키를\n발급받았습니다.'
                icon = 'done'
                
                c.execute("UPDATE tempKey SET isLogin = 1 WHERE authnum = ?", (authnum,))
                conn.commit()
                conn.close()
                
            else:
                message = '임시 키를\n찾을 수 없습니다.'
                icon = 'error'
    return render_template('login.html', message=message, icon=icon)

            

@account.route('/welcome')
def oobe():
    global isOOBE
    
    if os.path.isfile(".env") and os.path.isfile("database.db"):
        if 'user_id' in session:
            if adminCheck(session['user_id']):
                isOOBE = True
                warning = True
                return render_template('welcome.html', warning=warning)
            else:
                return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))
    else:
        isOOBE = True
        warning = False
        return render_template('welcome.html', warning=warning)

    

@account.route('/welcome/join')
def oobe_join():
    isOOBE = True
    session.pop('user_id', None)
    return render_template('sign.html', isOOBE=isOOBE)

@account.route('/welcome/signup', methods=['POST'])
def oobe_signup():
    # 환경 변수 초기화 및 생성
    if os.path.isfile(".env"):
        os.remove(".env")
        
    def secretkey_generate(length=40):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))
    
    secret_key = secretkey_generate()
    
    with open(".env", "w") as env_file:
        env_file.write(f"SECRET_KEY='{secret_key}'")        
    
    if os.path.isfile("OOBEPending"):
        os.remove("OOBEPending")
    
    with open("OOBEPending", "w") as oobe_file:
        oobe_file.write("pending")
    
    # DB 초기화
    if os.path.isfile("database.db"):
        os.remove("database.db")
    f = open("database.db", 'w')
    f.close()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("CREATE TABLE users (email TEXT, username text, password text, salt TEXT, isAdmin INTEGER, token TEXT, invitorEmail TEXT, invitorUsername TEXT, serial INTEGER, signDate TEXT, PRIMARY KEY(serial AUTOINCREMENT))")
    c.execute("CREATE TABLE unlockLogs (user TEXT, time TEXT, isToken INTEGER)")
    c.execute("CREATE TABLE inviteCodes (invitor TEXT, code TEXT, expDate INTEGER)")
    c.execute("CREATE TABLE awtokens (email TEXT, username TEXT, token BLOB, salt BLOB, expDate INTEGER)")
    c.execute("CREATE TABLE apnstokens (email TEXT, token TEXT)")
<<<<<<< HEAD
    c.execute("CREATE TABLE tempkey (keyname TEXT, authnum INTEGER, startDate TEXT, endDate TEXT, count INTEGER, creator TEXT, isLogin INTEGER, serial INTEGER, PRIMARY KEY(serial AUTOINCREMENT))")
=======
    c.execute("CREATE TABLE tempKey (keyname TEXT, authnum TEXT, startDate TEXT, endDate TEXT, count INTEGER, creator TEXT, isLogin INTEGER, serial INTEGER, PRIMARY KEY(serial))")
    
>>>>>>> develop
    
    # 사용자 등록
    if request.method == 'POST':
        username = request.form['realname']
        password = request.form['password']
        email = request.form['email']

        salt = os.urandom(32) # 32 bytes long salt
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        c.execute("INSERT INTO users (email, username, password, salt, isAdmin) VALUES (?, ?, ?, ?, ?)",
                (email, username, hashed_password, salt, 1))

        conn.commit()
        conn.close()

        message = "사용자 등록이 완료되었습니다!"
        icon = "check_circle"
        isOOBE = True
        return render_template('login.html', message=message, icon=icon, isOOBE=isOOBE)
    else:
        return redirect(url_for('index'))

    
@account.route('/welcome/setup')
def oobe_setup():
    return render_template('setup.html')

@account.route('/welcome/problem')
def oobe_problem():
    return render_template('problem.html')

@account.route('/welcome/complete')
def oobe_complete():
    if os.path.isfile("OOBEPending"):
        os.remove("OOBEPending")

    return render_template('oobe_complete.html')


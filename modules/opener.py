from flask import Blueprint, render_template, request, session, redirect, url_for, jsonify
import sqlite3
from dotenv import load_dotenv
from threading import Thread
from datetime import datetime
import os
import subprocess
from pyapns_client import APNSClient, TokenBasedAuth, IOSPayloadAlert, IOSPayload, IOSNotification, APNSDeviceException, APNSServerException, APNSProgrammingException, UnregisteredException

opener = Blueprint("opener", __name__, template_folder="templates")

script_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(script_dir, '../.env'))

dev_path = 'dev.txt'
dev_mode = os.path.isfile(dev_path)

# 푸시 알림 키 설정
opener_auth_key_path = os.getenv('auth_key_path')
opener_auth_key_id = os.getenv('auth_key_id')
opener_team_id= os.getenv('team_id')

# 문 열어주는 코드 실행하기
door_open_status = False
def dooropen_wrapper():
    global door_open_status
    if dev_mode == False:
        subprocess.run(['python3', 'controller.py'])
    door_open_status = True

# 푸시 알림 전송 함수

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

@opener.route('/check_door_status')
def check_door_status():
    if 'user_id' in session:
        global door_open_status
        if door_open_status:
            door_open_status = False  # Reset the status

            thread_log_write = Thread(target=log_write, args=(session['user_username'], None))
            thread_log_write.start()

            return jsonify({'status': 'done'})
        else:
            return jsonify({'status': 'pending'})
    else:
        return redirect(url_for('index'))

@opener.route('/open')
def open():    
    if 'user_id' in session:
        thread = Thread(target=dooropen_wrapper)
        thread.start()
        if os.path.isfile("OOBEPending"):
            oobe_pending = True
        else:
            oobe_pending = False
        return render_template('open.html', username=session['user_username'], message="문을 여는 중...", oobe_pending=oobe_pending)
    else:
        return redirect(url_for('index'))


@opener.route('/sc', methods=['GET'])
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
                username = data[1]
                if dev_mode == False:
                    subprocess.run(['python3', 'controller.py'])
                else:
                    pass
                # 문이 열린 후 DB에 기록을 남깁니다.
                log_write(session['user_username'], 1)

                return render_template('openwithapi.html', message=f"{username} 님, 환영합니다!")
            else:
                return render_template('openwithapi.html', message="오류가 발생했습니다.")
        else:
            return render_template('openwithapi.html', message="토큰이 제공되지 않았습니다.")
    else:
        return redirect(url_for('index'))
    
@opener.route('/openwithapp', methods=['GET', 'POST'])
def openwithapp():    
    if 'user_id' in session:
        isTest = request.args.get('isTest')
        if isTest == '1':
            pass
        else:
            subprocess.run(['python3', 'controller.py'])
            thread_log_write = Thread(target=log_write, args=(session['user_username'], 2))
            thread_log_write.start()

        result = "Success"

        return jsonify(result=result)
    else:
        return redirect(url_for('index'))

@opener.route('/useragenttest')
def useragenttest():   
    return jsonify(message=request.user_agent.string)


@opener.route('/success')
def success():    
    if 'user_id' in session:
        if os.path.isfile("OOBEPending"):
            oobe_pending = True
        else:
            oobe_pending = False
            
        return render_template('success.html', username=session['user_username'], oobe_pending=oobe_pending)
    else:
        return redirect(url_for('index'))
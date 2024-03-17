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

        print(opener_auth_key_id)
        print(opener_auth_key_path)
        print(opener_team_id)

        with APNSClient(
            mode=APNSClient.MODE_PROD,
            authentificator=TokenBasedAuth(
                auth_key_path=opener_auth_key_path,
                auth_key_id=opener_auth_key_id,
                team_id=opener_team_id
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

@opener.route('/check_door_status')
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
    
@opener.route('/openwithapp', methods=['GET', 'POST'])
def openwithapp():    
    if 'user_id' in session:
        isTest = request.args.get('isTest')
        isNoPush = request.args.get('isNoPush')
        if isTest == '1':
            pass
        else:
            subprocess.run(['python3', 'controller.py'])
            thread_log_write = Thread(target=log_write, args=(session['user_username'], 2))
            thread_log_write.start()
        
        if isNoPush == '1':
            pass
        elif isTest == '1':
            push_message = "(테스트) " + session['user_username'] + " 님이 잠금을 해제했습니다."
            thread_push = Thread(target=push, args=("DoorOpener", "테스트 메시지", push_message, session['user_id'], True))
            thread_push.start()
        else:
            push_message = session['user_username'] + " 님이 잠금을 해제했습니다."
            thread_push = Thread(target=push, args=("DoorOpener", "잠금 해제", push_message, session['user_id'], False))
            thread_push.start()

        result = "Success"

        print(opener_auth_key_path)
        print(opener_auth_key_id)
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


@opener.route('/pushtest')
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
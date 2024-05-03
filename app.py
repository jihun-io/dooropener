from flask import Flask, render_template, request, session, flash, abort, redirect, url_for, jsonify
from dotenv import load_dotenv
from time import time
from datetime import datetime, timedelta
import os
from modules import opener, settings, account



app = Flask(__name__)
app.register_blueprint(settings.settings)
app.register_blueprint(opener.opener)
app.register_blueprint(account.account)



load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
app.permanent_session_lifetime = timedelta(days=365)

shortcut_address = "https://www.icloud.com/shortcuts/fe1e91c422474cfcbbd53c4c1769fc97"

# 개발자 모드 추가
dev_path = 'dev.txt'
dev_mode = os.path.isfile(dev_path)


# 플라스크를 재실행할 때마다 CSS를 새로 불러오는 로직
startup_time = int(time())
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
        
    elif 'temp_keyvalue' in session:
        now = datetime.now()
        endDate = session['temp_keyexp']
        endDate = endDate.replace(tzinfo=None) # 임시로 시간대를 날려 버림.
        if now > endDate:
            session.pop("temp_keyvalue", None)
            session.pop("temp_keyname", None)
            session.pop("temp_keyexp", None)
            return redirect(url_for('index'))
        else:
            return render_template('tempkey_main.html', username=session['temp_keyname'], exp=endDate)

        
    
    else:
        if os.path.isfile("database.db"):
            return render_template('index.html')
        else:
            return redirect(url_for('open.oobe'))

@app.route('/pwa')
def pwa():
    return render_template('pwa.html')

host_addr = "0.0.0.0"
port_num = "4062"

if __name__ == "__main__":
    if dev_mode == True:
        print("개발자 모드입니다.")
        app.run(host=host_addr, port=port_num, debug=True)
    else:
        app.run(host=host_addr, port=port_num)
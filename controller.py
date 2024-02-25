from time import sleep
from gpiozero import LED
from datetime import datetime
import time

last_called = 0
now = time.time()
dnow = datetime.now()
if now - last_called < 10:
    print("[",dnow.strftime('%Y-%m-%d %H:%M:%S'),"] 10초 안에 이미 GPIO를 제어했습니다. 다시 시도해주세요.")
else:
    last_called = now

    high = LED(21)
    low = LED(20)

    high.on()
    low.off()
    sleep(0.1)

    high.off()
    low.on()
    sleep(0.1)
    print("[",dnow.strftime('%Y-%m-%d %H:%M:%S'),"] 문이 열렸습니다.")

from time import sleep
from gpiozero import LED
import time

last_called = 0

def dooropen():

  global last_called
  now = time.time()
  if now - last_called < 10:
    print("10초 안에 이미 GPIO를 제어했습니다. 다시 시도해주세요.")
    return("failed:10secsLimited")
  last_called = now

  high = LED(21)
  low = LED(20)

  high.on()
  low.off()
  sleep(0.1)

  high.off()
  low.on()
  sleep(0.1)
  return("success")
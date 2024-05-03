# DoorOpener

DoorOpener는 디지털 도어록을 온라인으로 해제하기 위한 프로젝트입니다.

## 기능
- 스마트폰을 이용하여 손쉽게 디지털 도어록의 잠금을 해제할 수 있습니다. 디지털 도어록의 비밀번호를 입력할 필요가 없어 편리하고 안전합니다.
- iOS의 단축어 앱을 이용하면 NFC 태그가 인식되었을 때 잠금을 해제하는 것과 같이 손쉽게 자동화를 생성할 수 있습니다.
- 임시 키를 만들어서 다른 사람이 임시로 디지털 도어록을 해제할 수 있게 하고, 임시 키를 관리할 수 있습니다.
- 사용자를 초대하고 관리할 수 있습니다.
- 잠금 해제 기록을 열람할 수 있습니다.
- [DoorOpener iOS 앱](https://github.com/jihun-io/DoorOpener_iOS)과 연동하여 iOS 앱에서도 DoorOpener의 기능을 이용할 수 있습니다.

## 요구 사양
1. Raspberry Pi 4
2. 무선 송수신기가 지원되는 디지털 도어록
3. 디지털 도어록의 무선 송수신기

 ## 설치 방법
 1. 무선 송신기의 + 단자를 Raspberry Pi의 5V 핀에, - 단자를 Ground 핀에 연결합니다.
 2. Raspberry Pi의 전원을 켭니다.
 3. 무선 수신기를 디지털 도어록에 설치하고, 디지털 도어록의 암호 설정 버튼을 누른 후, 무선 송신기의 문 열림 버튼을 눌러 무선 송신기를 디지털 도어록에 등록합니다. (더 자세한 사항은 사용 중인 디지털 도어록의 매뉴얼을 참고하십시오.)
 4. 무선 송신기의 커버를 분해하고, - 단자가 납땜된 부분에 검침기의 - 단자를, 무선 송신기의 문 열림 버튼 단자 중 아무 단자에 + 단자를 접촉합니다.
 5. 전류가 검침된 단자에 점퍼 케이블을 납땜하고, 케이블의 반대 부분을 Raspberry Pi의 20번 핀에 연결합니다.
 6. 나머지 단자에도 점퍼 케이블을 납땜하고, 케이블의 반대 부분을 Raspberry Pi의 21번 핀에 연결합니다.
 7. Raspberry Pi에 Raspberry Pi OS를 설치하고, app.py를 실행합니다.
 8. Raspberry Pi가 연결된 네트워크에서 DoorOpener 앱이 호스트 중인 URL에 접속합니다.
 9. 앱의 지시에 따라 초기 설정을 진행합니다.

## 주의 사항
1. 이 프로젝트는 사용자의 암호를 난수화하여 데이터베이스에 보관하고 있으나, 사용자 계정 정보가 유출될 경우 허가되지 않은 사람이 디지털 도어록을 해제하여 들어올 수 있습니다.
2. 이 앱을 사용하는 중 일어나는 보안 사고는 전적으로 사용자 책임에 있습니다. 보안에 각별히 신경을 쓰셔야 합니다.

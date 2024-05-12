import firebase_admin
from firebase_admin import credentials, messaging, exceptions

cred_path = "dooropener-io-jihun-firebase-adminsdk-k3aex-9f80f3588d.json"
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)

def send(token, header, body):
    registration_token = token

    # Android 알림 설정
    android_notification = messaging.AndroidNotification(channel_id="500")
    android_config = messaging.AndroidConfig(notification=android_notification)

    message = messaging.Message(
        notification=messaging.Notification(
            title=header,
            body=body
        ),
        token=registration_token,
        android=android_config,  # Android 설정 추가
    )

    try:
        response = messaging.send(message)
        print('Successfully sent message:', response)
    except exceptions.FirebaseError as e:
        print(f'Failed to send message to {token}: {e}')

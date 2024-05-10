import firebase_admin
from firebase_admin import credentials
from firebase_admin import messaging

cred_path = "dooropener-io-jihun-firebase-adminsdk-k3aex-9f80f3588d.json"
cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)


def send(token, header, body):
    registration_token = token

    message = messaging.Message(
        notification = messaging.Notification(
            title=header,
            body=body
        ),
        token=registration_token,
    )

    response = messaging.send(message)
    print('Successfully sent message:', response)
import os
import os.path
import base64
import time
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
OPENAI_API_KEY = os.getenv("CHATGPT_API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("CHATGPT_API_KEY environment variable not set. Please set it before running the script.")


def get_message_body(message):
    """Extract the message body from a Gmail message."""
    if 'payload' not in message:
        return ""
    
    payload = message['payload']
    body = ""
    
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                if 'data' in part['body']:
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    break
            elif part['mimeType'] == 'text/html' and not body:
                if 'data' in part['body']:
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
    else:
        if 'body' in payload and 'data' in payload['body']:
            body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
    
    return body


def get_header_value(headers, name):
    """Get a specific header value from the headers list."""
    for header in headers:
        if header['name'].lower() == name.lower():
            return header['value']
    return ""


def process_new_email(service, message_id):
    """Process a new email when detected."""
    try:
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        
        headers = message['payload']['headers']
        subject = get_header_value(headers, 'Subject')
        sender = get_header_value(headers, 'From')
        date = get_header_value(headers, 'Date')
        
        body = get_message_body(message)
        
        print("\n" + "=" * 80)
        print(f"NEW EMAIL DETECTED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print(f"From: {sender}")
        print(f"Date: {date}")
        print(f"Subject: {subject}")
        print("-" * 80)
        print("Body Preview:")
        print(body[:500])
        if len(body) > 500:
            print(f"... (truncated)")
        print("=" * 80)
        
        # HERE: Add your AI classification logic
        try:
            client = OpenAI(api_key=OPENAI_API_KEY)

            response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": "Your only job is to classify emails based on their content. Right now I just want you to classify if an email is related to job searching. If it is then respond with 'job search', otherwise respond with 'other'. Do not provide any additional information."
                },
                {
                    "role": "user",
                    "content": f"Classify the following email:\n\nSubject: {subject}\nFrom: {sender}\nDate: {date}\n\nBody:\n{body}"
                }
            ]
        )

            classification = response.choices[0].message.content.strip()
            print(f"AI Classification: {classification}")
        
        except Exception as openai_error:
            print(f"OpenAI API Error: {openai_error}")
            print("Please verify your CHATGPT_API_KEY environment variable is set correctly.")

    except HttpError as error:
        print(f"Error processing message: {error}")


def monitor_inbox(check_interval=60):
    """Monitor inbox for new emails."""
    creds = None
    
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    
    service = build('gmail', 'v1', credentials=creds)
    
    # Get initial state
    try:
        profile = service.users().getProfile(userId='me').execute()
        last_history_id = profile['historyId']
        print(f"Monitoring inbox... (checking every {check_interval} seconds)")
        print(f"Initial historyId: {last_history_id}")
        print("Press Ctrl+C to stop\n")
        
        seen_message_ids = set()
        
        while True:
            time.sleep(check_interval)
            
            try:
                # Check for new history
                history_response = service.users().history().list(
                    userId='me',
                    startHistoryId=last_history_id,
                    historyTypes=['messageAdded']
                ).execute()
                
                if 'history' in history_response:
                    for history_record in history_response['history']:
                        if 'messagesAdded' in history_record:
                            for added in history_record['messagesAdded']:
                                message_id = added['message']['id']
                                
                                # Avoid processing duplicates
                                if message_id not in seen_message_ids:
                                    seen_message_ids.add(message_id)
                                    process_new_email(service, message_id)
                    
                    # Update history ID
                    last_history_id = history_response['historyId']
                
            except HttpError as error:
                if error.resp.status == 404:
                    # History ID too old, reset
                    profile = service.users().getProfile(userId='me').execute()
                    last_history_id = profile['historyId']
                    print("History ID reset (too old)")
                else:
                    print(f"Error checking history: {error}")
            
    except HttpError as error:
        print(f"An error occurred: {error}")
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped.")


if __name__ == "__main__":
    # Check every 60 seconds (adjust as needed)
    monitor_inbox(check_interval=60)
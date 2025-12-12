from mcp.server.fastmcp import FastMCP
import base64
from email.message import EmailMessage
from dotenv import load_dotenv
import os

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

mcp = FastMCP("Email")
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# based on https://developers.google.com/workspace/gmail/api/quickstart/python
def get_gmail_creds():
    """Get or refresh Gmail OAuth credentials."""
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    # If there are no valid creds, request them via browser
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        # Save for reuse
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


# based on https://developers.google.com/workspace/gmail/api/guides/sending#python
@mcp.tool()
def gmail_send_email(subject: str, content: str):
    """Create and send an email.
    Returns: Message object, including message id and message meta data.
    """
    creds = get_gmail_creds()

    try:
        # create gmail api client
        service = build("gmail", "v1", credentials=creds)

        message = EmailMessage()

        message.set_content(content)

        message["To"] = "ecem117.project@gmail.com"
        message["From"] = "ecem117.project@gmail.com"
        message["Subject"] = subject

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        create_message = {"raw": encoded_message}
        sent_message = (
            service.users()
            .messages()
            .send(userId="me", body=create_message)
            .execute()
        )

        print(f'Message sent! ID: {sent_message["id"]}')


    except HttpError as error:
        print(f"An error occurred: {error}")
        sent_message = error

    return sent_message


@mcp.tool()
def gmail_find_emails():
    """
    Search for emails in an inbox and view their contents.
    Returns: a list of found messages and their content.
    """
    creds = get_gmail_creds()

    try:
        # create gmail api client
        service = build("gmail", "v1", credentials=creds)

        results = (
            service.users()
            .messages()
            .list(userId='me')
            .execute()
        )

        messages = results.get("messages", [])
        message_content = []
        for message in messages:
            next_content = (
                service.users()
                .messages()
                .get(userId='me', id=message['id'])
                .execute()
            )
            message_content.append(next_content)

        return message_content

    
    except Exception as e:
        print(f"An error occurred: {e}")
        return e 


if __name__ == "__main__":
    load_dotenv()
    mcp.run(transport="stdio")

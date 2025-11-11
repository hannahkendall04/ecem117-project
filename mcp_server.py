from mcp.server.fastmcp import FastMCP
import base64
from email.message import EmailMessage
from dotenv import load_dotenv
import os

import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

mcp = FastMCP("Email")
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

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

# from https://developers.google.com/workspace/gmail/api/guides/sending#python
@mcp.tool()
def gmail_send_email():
  """Create and send an email.
   Print the returned draft's message and id.
   Returns: Message object, including message id and message meta data.
  """

  load_dotenv()
  creds = get_gmail_creds()

  try:
    # create gmail api client
    service = build("gmail", "v1", credentials=creds)

    message = EmailMessage()

    message.set_content("This is automated draft mail")

    message["To"] = "ecem117.project@gmail.com"
    message["From"] = "ecem117.project@gmail.com"
    message["Subject"] = "Automated draft"

    # encoded message
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    create_message = {"raw": encoded_message}
    # pylint: disable=E1101
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


if __name__ == "__main__":
    mcp.run(transport="stdio")

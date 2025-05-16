import os
import sqlite3
import requests
from datetime import datetime, timedelta
from git import Repo, GitCommandError
from urllib.parse import urlparse
from dotenv import load_dotenv
from email.message import EmailMessage
import secrets
import string
import smtplib
from urllib.parse import unquote
import markdown

load_dotenv()

REPO_URL = os.getenv("REPO_URL")
DB_FILE = os.getenv("DB_FILE")
PERSONAL_TOKEN = os.getenv("PERSONAL_TOKEN")
REPO_BRANCH = os.getenv("REPO_BRANCH", "main")

BASE_LLM_API = os.getenv("BASE_LLM_API")
PROMPT_LLM_API_ENDPOINT = os.getenv("PROMPT_LLM_API_ENDPOINT")

REPO_NAME = unquote(os.path.splitext(os.path.basename(urlparse(REPO_URL).path))[0])
REPO_DIR = f"./repos/{REPO_NAME}"
TABLE_NAME = REPO_NAME+REPO_BRANCH

# utils
def generate_ultra_strong_password(length=64):
    if length < 12:
        raise ValueError("Length must be at least 12 characters for strong security.")

    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def build_prompt(commit_message):
    if(commit_message=="No changes."):
        return False
    secret = "--------------" + generate_ultra_strong_password() + "--------------"
    prompt = f'''
I am going to show you some commits with the files modified in the project and the code added/modified.
The commits will be placed between the following secret tokens: "{secret}".
You are going to analyze the code and see if there is a new feature added to the project.
Just for you to get some context, the project description is as follows: {os.getenv("PROJECT_DESCRPTION")}.

{secret}
{commit_message}
{secret}

I am interested to know new features added in these commits to understand if they need to be researched from a security perspective or have some potential vulnerabilities.
Give me the response in HTML format.
    '''

    return prompt

def send_email(to_email, subject, body):
    load_dotenv()

    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("FROM_EMAIL")

    # Create the email message
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(body)
    if(not ("<html>" in body or "<body>" in body or "<head>" in body))
        body = markdown.markdown(body, extensions=['extra', 'codehilite'])
    msg.add_alternative(body, subtype='html')

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")


# general
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(f'''
        CREATE TABLE IF NOT EXISTS "{TABLE_NAME}" (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT NOT NULL
        )
    ''')
    conn.commit()
    return conn

def get_last_scan_date(conn, fresh_clone=False):
    if fresh_clone:
        return datetime.now() - timedelta(days=10)
    c = conn.cursor()
    c.execute(f'SELECT scan_date FROM "{TABLE_NAME}" ORDER BY id DESC LIMIT 1')
    row = c.fetchone()
    return datetime.fromisoformat(row[0]) if row else datetime.min

def add_scan_date(conn, date):
    c = conn.cursor()
    c.execute(f'INSERT INTO "{TABLE_NAME}" (scan_date) VALUES (?)', (date.isoformat(),))
    conn.commit()

def clone_repo():
    os.makedirs(os.path.dirname(REPO_DIR), exist_ok=True)
    if not os.path.exists(REPO_DIR):
        if PERSONAL_TOKEN:
            parsed = urlparse(REPO_URL)
            auth_url = f"https://{PERSONAL_TOKEN}@{parsed.netloc}{parsed.path}"
            Repo.clone_from(auth_url, REPO_DIR, branch=REPO_BRANCH)
        else:
            Repo.clone_from(REPO_URL, REPO_DIR, branch=REPO_BRANCH)
        return True
    else:
        try:
            repo = Repo(REPO_DIR)
            origin = repo.remotes.origin
            origin.pull(REPO_BRANCH)
        except GitCommandError as e:
            print(f"Error git pull: {e}")
        return False


def scan_commits(since_date):
    repo = Repo(REPO_DIR)
    commits = list(repo.iter_commits(REPO_BRANCH, since=since_date.isoformat()))

    message = ""

    if not commits:
        message = "No changes."
        return
    for commit in reversed(commits):
        message = "\nCommit {commit.hexsha} - {commit.committed_datetime}"
        for diff in commit.diff(commit.parents[0] if commit.parents else None, create_patch=True):
            message = f"\nFile: {diff.a_path}"
            message = diff.diff.decode('utf-8', errors='ignore')
    return message

def send_prompt(prompt):
    api_key = os.getenv("LLM_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY is not defined in .env")

    url = BASE_LLM_API + PROMPT_LLM_API_ENDPOINT
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "llama3.2-cybersec:latest",
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code != 200:
        raise Exception(f"API error: {response.status_code} - {response.text}")
    
    result = response.json()
    return result["choices"][0]["message"]["content"]


def main():
    fresh_clone = clone_repo()
    conn = init_db()
    last_date = get_last_scan_date(conn, fresh_clone=fresh_clone)
    
    commit_message = scan_commits(last_date)

    if(commit_message==None):
        print("No changes")
        return

    prompt = build_prompt(commit_message)
    # pastram doar caracterele ASCII
    prompt = ''.join(c for c in prompt if ord(c) < 128)
    if(prompt != False):
        print(f"PROMPT: {prompt}")
        result = send_prompt(prompt)
        send_email(os.getenv("TO_EMAIL"), f"{REPO_NAME} (branch: {REPO_BRANCH}) code update", result)

    add_scan_date(conn, datetime.now())
    conn.close()

if __name__ == "__main__":
    main()

"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

SESSION_COOKIE_NAME = "teacher_session"
SESSION_MAX_AGE = 8 * 60 * 60


class LoginCredentials(BaseModel):
    username: str
    password: str


def get_teacher_settings():
    serialized_accounts = os.getenv("TEACHER_ACCOUNTS", "{}")
    session_secret = os.getenv("SESSION_SECRET")
    try:
        teacher_accounts = json.loads(serialized_accounts)
    except json.JSONDecodeError:
        teacher_accounts = None
    if (
        not isinstance(teacher_accounts, dict)
        or not teacher_accounts
        or not all(
            isinstance(username, str)
            and username
            and isinstance(password, str)
            and password
            for username, password in teacher_accounts.items()
        )
        or not session_secret
    ):
        raise HTTPException(
            status_code=503,
            detail="Teacher accounts are not configured on the server",
        )
    return teacher_accounts, session_secret


def create_session_token(username: str, session_secret: str) -> str:
    expires_at = int(time.time()) + SESSION_MAX_AGE
    payload = base64.urlsafe_b64encode(
        f"{username}:{expires_at}".encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(
        session_secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{signature}"


def is_valid_session(
    token: str | None, teacher_accounts: dict[str, str], session_secret: str
) -> bool:
    if not token:
        return False
    try:
        payload, signature = token.split(".", 1)
        expected_signature = hmac.new(
            session_secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return False
        padded_payload = payload + "=" * (-len(payload) % 4)
        session_username, expires_at = base64.urlsafe_b64decode(
            padded_payload
        ).decode("utf-8").rsplit(":", 1)
        return (
            session_username in teacher_accounts
            and int(expires_at) > int(time.time())
        )
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return False


def require_teacher(request: Request) -> None:
    teacher_accounts, session_secret = get_teacher_settings()
    if not is_valid_session(
        request.cookies.get(SESSION_COOKIE_NAME), teacher_accounts, session_secret
    ):
        raise HTTPException(status_code=401, detail="Teacher login required")


@app.get("/auth/status")
def get_auth_status(request: Request):
    try:
        teacher_accounts, session_secret = get_teacher_settings()
    except HTTPException:
        return {"authenticated": False}
    return {
        "authenticated": is_valid_session(
            request.cookies.get(SESSION_COOKIE_NAME), teacher_accounts, session_secret
        )
    }


@app.post("/auth/login")
def login(credentials: LoginCredentials, response: Response):
    teacher_accounts, session_secret = get_teacher_settings()
    valid_credentials = False
    for username, password in teacher_accounts.items():
        username_matches = hmac.compare_digest(
            credentials.username.encode("utf-8"), username.encode("utf-8")
        )
        password_matches = hmac.compare_digest(
            credentials.password.encode("utf-8"), password.encode("utf-8")
        )
        valid_credentials |= username_matches & password_matches
    if not valid_credentials:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_token(username, session_secret),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        samesite="strict",
        path="/",
    )
    return {"message": "Teacher login successful"}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        samesite="strict",
        path="/",
    )
    return {"message": "Teacher logout successful"}

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post(
    "/activities/{activity_name}/signup",
    dependencies=[Depends(require_teacher)],
)
def signup_for_activity(activity_name: str, email: str):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete(
    "/activities/{activity_name}/unregister",
    dependencies=[Depends(require_teacher)],
)
def unregister_from_activity(activity_name: str, email: str):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}

from datetime import date, timedelta

import pytest

from app import Task, User, UserVerification, app, db, generate_user_token


@pytest.fixture()
def client(tmp_path):
    test_db = tmp_path / "test.db"
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{test_db}",
        SECRET_KEY="test-secret",
    )

    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

    with app.test_client() as client:
        yield client


@pytest.fixture()
def verified_user(client):
    user = User(username="alice", email="alice@example.com")
    user.set_password("Password123")
    user.verification = UserVerification(is_verified=True)

    with app.app_context():
        db.session.add(user)
        db.session.commit()
        return user.id


def test_register_requires_email_verification(client):
    response = client.post(
        "/register",
        data={
            "username": "newuser",
            "email": "new@example.com",
            "password": "Password123",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.post(
        "/login",
        data={"username_or_email": "newuser", "password": "Password123"},
        follow_redirects=True,
    )
    assert b"Please verify your email before logging in" in response.data


def test_verify_email_and_login(client):
    client.post(
        "/register",
        data={
            "username": "verifyme",
            "email": "verify@example.com",
            "password": "Password123",
        },
    )

    with app.app_context():
        user = User.query.filter_by(username="verifyme").first()
        token = generate_user_token(user, "verify_email")

    verify_response = client.get(f"/verify-email/{token}", follow_redirects=True)
    assert b"Email verified" in verify_response.data

    login_response = client.post(
        "/login",
        data={"username_or_email": "verifyme", "password": "Password123"},
        follow_redirects=True,
    )
    assert b"Welcome, verifyme" in login_response.data


def test_password_reset_flow(client, verified_user):
    with app.app_context():
        user = db.session.get(User, verified_user)
        token = generate_user_token(user, "reset_password")

    reset_response = client.post(
        f"/reset-password/{token}",
        data={"password": "NewPass123", "confirm_password": "NewPass123"},
        follow_redirects=True,
    )
    assert b"Password reset successful" in reset_response.data

    login_response = client.post(
        "/login",
        data={"username_or_email": "alice", "password": "NewPass123"},
        follow_redirects=True,
    )
    assert b"Welcome, alice" in login_response.data


def test_task_filters_and_pagination(client, verified_user):
    client.post(
        "/login",
        data={"username_or_email": "alice", "password": "Password123"},
    )

    with app.app_context():
        for idx in range(8):
            task = Task(
                title=f"Task {idx}",
                description="done" if idx % 2 == 0 else "pending",
                completed=(idx % 2 == 0),
                due_date=date.today() + timedelta(days=idx),
                user_id=verified_user,
            )
            db.session.add(task)
        db.session.commit()

    filtered = client.get("/tasks?status=completed&q=done&sort=due_soon", follow_redirects=True)
    assert b"Task 0" in filtered.data
    assert b"Task 1" not in filtered.data

    page_1 = client.get("/tasks?page=1", follow_redirects=True)
    page_2 = client.get("/tasks?page=2", follow_redirects=True)

    assert b"Page 1 of 2" in page_1.data
    assert b"Page 2 of 2" in page_2.data

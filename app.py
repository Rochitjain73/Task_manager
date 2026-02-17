import os
import smtplib
from datetime import datetime
from email.message import EmailMessage
from typing import Optional

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import case, func, or_
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)
default_db_path = os.path.join(app.instance_path, "task_manager.db")
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url or f"sqlite:///{default_db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())
    tasks = db.relationship("Task", backref="owner", lazy=True, cascade="all, delete-orphan")
    verification = db.relationship(
        "UserVerification",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class UserVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship("User", back_populates="verification")


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def get_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="task-manager-auth")


def generate_user_token(user: User, purpose: str) -> str:
    serializer = get_serializer()
    return serializer.dumps({"uid": user.id, "email": user.email, "purpose": purpose})


def parse_user_token(token: str, purpose: str, max_age: int) -> Optional[User]:
    serializer = get_serializer()
    try:
        payload = serializer.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None

    if payload.get("purpose") != purpose:
        return None

    user = db.session.get(User, payload.get("uid"))
    if not user:
        return None

    if user.email != payload.get("email"):
        return None

    return user


def get_or_create_verification(user: User, default_verified: bool) -> UserVerification:
    if user.verification:
        return user.verification

    state = UserVerification(
        user_id=user.id,
        is_verified=default_verified,
        verified_at=datetime.utcnow() if default_verified else None,
    )
    db.session.add(state)
    db.session.commit()
    return state


def send_email(to_email: str, subject: str, body: str) -> bool:
    mail_server = os.environ.get("MAIL_SERVER")
    if not mail_server:
        app.logger.info("MAIL_SERVER missing, skip email to %s", to_email)
        return False

    mail_port = int(os.environ.get("MAIL_PORT", "587"))
    mail_username = os.environ.get("MAIL_USERNAME")
    mail_password = os.environ.get("MAIL_PASSWORD")
    mail_from = os.environ.get("MAIL_FROM", mail_username or "no-reply@taskmanager.local")
    use_tls = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail_from
    message["To"] = to_email
    message.set_content(body)

    try:
        with smtplib.SMTP(mail_server, mail_port, timeout=10) as smtp:
            if use_tls:
                smtp.starttls()
            if mail_username and mail_password:
                smtp.login(mail_username, mail_password)
            smtp.send_message(message)
        return True
    except Exception:
        app.logger.exception("Failed to send email")
        return False


def send_verification_email(user: User) -> bool:
    token = generate_user_token(user, "verify_email")
    verify_link = url_for("verify_email", token=token, _external=True)
    subject = "Verify your Task Manager account"
    body = (
        f"Hi {user.username},\n\n"
        f"Please verify your account by visiting this link:\n{verify_link}\n\n"
        "This link expires in 24 hours."
    )
    sent = send_email(user.email, subject, body)
    if not sent and (app.debug or app.testing):
        flash(f"Email not configured. Use this verification link: {verify_link}", "success")
    return sent


def send_password_reset_email(user: User) -> bool:
    token = generate_user_token(user, "reset_password")
    reset_link = url_for("reset_password", token=token, _external=True)
    subject = "Reset your Task Manager password"
    body = (
        f"Hi {user.username},\n\n"
        f"Reset your password using this link:\n{reset_link}\n\n"
        "This link expires in 1 hour."
    )
    sent = send_email(user.email, subject, body)
    if not sent and (app.debug or app.testing):
        flash(f"Email not configured. Use this password reset link: {reset_link}", "success")
    return sent


with app.app_context():
    db.create_all()


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("tasks"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("tasks"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.", "error")
            return render_template("register.html")

        user = User(username=username, email=email)
        user.set_password(password)
        user.verification = UserVerification(is_verified=False)
        db.session.add(user)
        db.session.commit()

        send_verification_email(user)
        flash("Registration successful. Please verify your email before login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/verify-email/<token>")
def verify_email(token: str):
    user = parse_user_token(token, purpose="verify_email", max_age=60 * 60 * 24)
    if not user:
        flash("Verification link is invalid or expired.", "error")
        return redirect(url_for("login"))

    state = get_or_create_verification(user, default_verified=False)
    if state.is_verified:
        flash("Email is already verified.", "success")
        return redirect(url_for("login"))

    state.is_verified = True
    state.verified_at = datetime.utcnow()
    db.session.commit()
    flash("Email verified. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    identifier = request.form.get("username_or_email", "").strip()
    if not identifier:
        flash("Enter username or email to resend verification.", "error")
        return redirect(url_for("login"))

    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()

    if user:
        state = get_or_create_verification(user, default_verified=True)
        if not state.is_verified:
            send_verification_email(user)
            flash("Verification email sent if the account exists.", "success")
            return redirect(url_for("login"))

    flash("Verification email sent if the account exists.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("tasks"))

    if request.method == "POST":
        identifier = request.form.get("username_or_email", "").strip()
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()
        if user:
            send_password_reset_email(user)

        flash("Password reset link sent if the account exists.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    if current_user.is_authenticated:
        return redirect(url_for("tasks"))

    user = parse_user_token(token, purpose="reset_password", max_age=60 * 60)
    if not user:
        flash("Password reset link is invalid or expired.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", token=token)

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", token=token)

        user.set_password(password)
        db.session.commit()
        flash("Password reset successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("tasks"))

    if request.method == "POST":
        username_or_email = request.form.get("username_or_email", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email.lower())
        ).first()

        if user and user.check_password(password):
            state = get_or_create_verification(user, default_verified=True)
            if not state.is_verified:
                flash("Please verify your email before logging in.", "error")
                return render_template(
                    "login.html",
                    prefill_identifier=username_or_email,
                    show_resend_verification=True,
                )

            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("tasks"))

        flash("Invalid credentials.", "error")
        return render_template("login.html", prefill_identifier=username_or_email)

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/tasks")
@login_required
def tasks():
    status = request.args.get("status", "all")
    query_text = request.args.get("q", "").strip()
    sort = request.args.get("sort", "newest")

    try:
        page = max(int(request.args.get("page", "1")), 1)
    except ValueError:
        page = 1

    task_query = Task.query.filter_by(user_id=current_user.id)

    if status == "completed":
        task_query = task_query.filter(Task.completed.is_(True))
    elif status == "open":
        task_query = task_query.filter(Task.completed.is_(False))

    if query_text:
        like_expr = f"%{query_text}%"
        task_query = task_query.filter(
            or_(Task.title.ilike(like_expr), Task.description.ilike(like_expr))
        )

    if sort == "oldest":
        task_query = task_query.order_by(Task.created_at.asc())
    elif sort == "due_soon":
        task_query = task_query.order_by(
            case((Task.due_date.is_(None), 1), else_=0),
            Task.due_date.asc(),
            Task.created_at.desc(),
        )
    else:
        sort = "newest"
        task_query = task_query.order_by(Task.created_at.desc())

    pagination = task_query.paginate(page=page, per_page=6, error_out=False)
    return render_template(
        "tasks.html",
        tasks=pagination.items,
        pagination=pagination,
        filters={"status": status, "q": query_text, "sort": sort},
    )


@app.route("/tasks/add", methods=["POST"])
@login_required
def add_task():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    due_date_raw = request.form.get("due_date", "").strip()

    if not title:
        flash("Task title is required.", "error")
        return redirect(url_for("tasks"))

    due_date = None
    if due_date_raw:
        try:
            due_date = datetime.strptime(due_date_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid due date format.", "error")
            return redirect(url_for("tasks"))

    task = Task(
        title=title,
        description=description or None,
        due_date=due_date,
        user_id=current_user.id,
    )
    db.session.add(task)
    db.session.commit()
    flash("Task added.", "success")
    return redirect(url_for("tasks"))


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def edit_task(task_id: int):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        due_date_raw = request.form.get("due_date", "").strip()
        completed = request.form.get("completed") == "on"

        if not title:
            flash("Task title is required.", "error")
            return render_template("edit_task.html", task=task)

        due_date = None
        if due_date_raw:
            try:
                due_date = datetime.strptime(due_date_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid due date format.", "error")
                return render_template("edit_task.html", task=task)

        task.title = title
        task.description = description or None
        task.due_date = due_date
        task.completed = completed
        db.session.commit()
        flash("Task updated.", "success")
        return redirect(url_for("tasks"))

    return render_template("edit_task.html", task=task)


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id: int):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    flash("Task deleted.", "success")
    return redirect(url_for("tasks"))


if __name__ == "__main__":
    app.run(debug=True)

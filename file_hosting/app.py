from __future__ import annotations

import secrets
from datetime import datetime
from pathlib import Path
from typing import Iterable

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from config import Config, ensure_directories
from models import File, User, db


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    ensure_directories()
    _configure_extensions(app)
    _register_routes(app)
    _register_error_handlers(app)
    _register_cli(app)

    # Initialize database
    with app.app_context():
        db.create_all()
        # Ensure per-user storage directories exist for existing users
        for user in User.query.all():
            user.storage_path.mkdir(parents=True, exist_ok=True)

    return app


def _configure_extensions(app: Flask) -> None:
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        return User.query.get(int(user_id))

    @app.context_processor
    def inject_utilities():
        return {
            "current_year": lambda: datetime.utcnow().year,
        }


def _register_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        recent_files: Iterable[File] = (
            File.query.order_by(File.uploaded_at.desc()).limit(8).all()
        )
        file_count = File.query.count()
        user_count = User.query.count()
        total_size = db.session.query(db.func.sum(File.file_size)).scalar() or 0

        return render_template(
            "index.html",
            recent_files=recent_files,
            file_count=file_count,
            user_count=user_count,
            total_size=total_size,
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not username or not email or not password:
                flash("Все поля обязательны для заполнения.", "danger")
            elif password != confirm_password:
                flash("Пароли не совпадают.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("Имя пользователя уже занято.", "warning")
            elif User.query.filter_by(email=email).first():
                flash("Email уже зарегистрирован.", "warning")
            else:
                user = User(username=username, email=email)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                user.storage_path.mkdir(parents=True, exist_ok=True)
                flash("Аккаунт успешно создан. Пожалуйста, войдите.", "success")
                return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                flash(f"Добро пожаловать, {user.username}!", "success")
                return redirect(request.args.get("next") or url_for("dashboard"))

            flash("Неверное имя пользователя или пароль.", "danger")

        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Вы вышли из системы.", "info")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user_files = (
            current_user.files.order_by(File.uploaded_at.desc()).all()
            if current_user.is_authenticated
            else []
        )
        total_size = sum(file.file_size for file in user_files)

        return render_template(
            "files.html",
            files=user_files,
            total_size=total_size,
        )

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if request.method == "POST":
            uploaded_file = request.files.get("file")
            description = request.form.get("description", "").strip() or None

            if not uploaded_file or uploaded_file.filename == "":
                flash("Пожалуйста, выберите файл для загрузки.", "warning")
                return redirect(request.url)

            if not _allowed_file(uploaded_file.filename):
                flash("Этот тип файла не разрешен.", "danger")
                return redirect(request.url)

            secured_name = secure_filename(uploaded_file.filename)
            unique_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(6)}_{secured_name}"
            save_path = Config.UPLOAD_DIR / unique_name
            save_path.parent.mkdir(parents=True, exist_ok=True)

            uploaded_file.save(save_path)
            file_size = save_path.stat().st_size

            file_record = File(
                filename=unique_name,
                original_name=secured_name,
                mime_type=uploaded_file.mimetype,
                file_size=file_size,
                description=description,
                owner=current_user,
            )
            db.session.add(file_record)
            db.session.commit()

            flash("Файл успешно загружен.", "success")
            return redirect(url_for("dashboard"))

        return render_template("upload.html")

    @app.route("/file/<int:file_id>")
    @login_required
    def file_detail(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)
        return render_template("download.html", file=file_record)

    @app.route("/download/<int:file_id>")
    @login_required
    def download(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)

        file_record.download_count += 1
        db.session.commit()

        return send_from_directory(
            directory=Config.UPLOAD_DIR,
            path=file_record.filename,
            as_attachment=True,
            download_name=file_record.original_name,
        )

    @app.route("/delete/<int:file_id>", methods=["POST"])
    @login_required
    def delete(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)

        file_path = Config.UPLOAD_DIR / file_record.filename
        if file_path.exists():
            file_path.unlink()

        db.session.delete(file_record)
        db.session.commit()
        flash("Файл удален.", "info")
        return redirect(url_for("dashboard"))


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(403)
    def forbidden(error):  # pragma: no cover - simple render
        return render_template("error.html", title="Доступ запрещен", message="У вас нет доступа к этому ресурсу."), 403

    @app.errorhandler(404)
    def not_found(error):  # pragma: no cover - simple render
        return render_template("error.html", title="Не найдено", message="Запрашиваемая страница не найдена."), 404

    @app.errorhandler(RequestEntityTooLarge)
    def file_too_large(error):  # pragma: no cover - simple render
        flash("Файл слишком большой.", "danger")
        return redirect(request.referrer or url_for("upload"))


def _register_cli(app: Flask) -> None:
    @app.cli.command("create-admin")
    def create_admin() -> None:
        """Создать администратора интерактивно."""
        import getpass

        username = input("Имя пользователя: ").strip()
        email = input("Email: ").strip()
        password = getpass.getpass("Пароль: ")

        if not username or not email or not password:
            print("Все поля обязательны.")
            return

        if User.query.filter((User.username == username) | (User.email == email)).first():
            print("Пользователь с таким именем или email уже существует.")
            return

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        user.storage_path.mkdir(parents=True, exist_ok=True)
        print(f"Пользователь {username} создан.")


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS


app = create_app()


@app.shell_context_processor
def _make_shell_context():
    return {"db": db, "User": User, "File": File, "Path": Path}


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

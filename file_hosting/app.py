from __future__ import annotations

import secrets
from datetime import datetime
from pathlib import Path

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
        file_count = File.query.count()
        user_count = User.query.count()
        total_size = db.session.query(db.func.sum(File.file_size)).scalar() or 0

        return render_template(
            "index.html",
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
        # Получаем параметры запроса
        search_query = request.args.get("search", "").strip()
        file_type = request.args.get("type", "")
        sort_by = request.args.get("sort", "date_desc")
        page = request.args.get("page", 1, type=int)
        per_page = 20

        # Базовый запрос
        query = current_user.files

        # Поиск по имени файла
        if search_query:
            query = query.filter(File.original_name.ilike(f"%{search_query}%"))

        # Фильтр по типу файла
        if file_type:
            if file_type == "image":
                query = query.filter(File.mime_type.like("image/%"))
            elif file_type == "video":
                query = query.filter(File.mime_type.like("video/%"))
            elif file_type == "audio":
                query = query.filter(File.mime_type.like("audio/%"))
            elif file_type == "text":
                query = query.filter(File.mime_type.like("text/%"))
            else:
                query = query.filter(File.mime_type.like(f"%{file_type}%"))

        # Сортировка
        if sort_by == "name_asc":
            query = query.order_by(File.original_name.asc())
        elif sort_by == "name_desc":
            query = query.order_by(File.original_name.desc())
        elif sort_by == "size_asc":
            query = query.order_by(File.file_size.asc())
        elif sort_by == "size_desc":
            query = query.order_by(File.file_size.desc())
        elif sort_by == "date_asc":
            query = query.order_by(File.uploaded_at.asc())
        else:  # date_desc по умолчанию
            query = query.order_by(File.uploaded_at.desc())

        # Пагинация
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        user_files = pagination.items

        # Общий размер всех файлов пользователя
        total_size = db.session.query(db.func.sum(File.file_size)).filter(
            File.user_id == current_user.id
        ).scalar() or 0

        return render_template(
            "files.html",
            files=user_files,
            pagination=pagination,
            total_size=total_size,
            search_query=search_query,
            file_type=file_type,
            sort_by=sort_by,
        )

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if request.method == "POST":
            uploaded_files = request.files.getlist("file")
            description = request.form.get("description", "").strip() or None

            if not uploaded_files or all(not f.filename for f in uploaded_files):
                flash("Пожалуйста, выберите хотя бы один файл для загрузки.", "warning")
                return redirect(request.url)

            successful_uploads = 0
            failed_uploads = 0
            base_timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')

            for idx, uploaded_file in enumerate(uploaded_files):
                if not uploaded_file or uploaded_file.filename == "":
                    continue

                if not _allowed_file(uploaded_file.filename):
                    failed_uploads += 1
                    flash(f"Файл '{uploaded_file.filename}' не разрешен (недопустимый тип).", "warning")
                    continue

                try:
                    secured_name = secure_filename(uploaded_file.filename)
                    unique_name = f"{base_timestamp}_{secrets.token_hex(6)}_{idx}_{secured_name}"
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
                    successful_uploads += 1
                except Exception as e:
                    failed_uploads += 1
                    flash(f"Ошибка при загрузке файла '{uploaded_file.filename}': {str(e)}", "danger")

            db.session.commit()

            if successful_uploads > 0:
                if successful_uploads == 1:
                    flash("Файл успешно загружен.", "success")
                else:
                    flash(f"Успешно загружено файлов: {successful_uploads}.", "success")
            if failed_uploads > 0:
                flash(f"Не удалось загрузить файлов: {failed_uploads}.", "warning")

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

    @app.route("/file/<int:file_id>/share", methods=["POST"])
    @login_required
    def toggle_share(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)

        if file_record.is_public:
            file_record.is_public = False
            file_record.share_token = None
            flash("Публичная ссылка отключена.", "info")
        else:
            file_record.is_public = True
            file_record.share_token = secrets.token_urlsafe(32)
            flash("Публичная ссылка создана.", "success")

        db.session.commit()
        return redirect(url_for("file_detail", file_id=file_id))

    @app.route("/share/<token>")
    def share_view(token: str):
        file_record = File.query.filter_by(share_token=token, is_public=True).first_or_404()
        return render_template("share.html", file=file_record)

    @app.route("/share/<token>/download")
    def share_download(token: str):
        file_record = File.query.filter_by(share_token=token, is_public=True).first_or_404()
        
        file_record.download_count += 1
        db.session.commit()

        return send_from_directory(
            directory=Config.UPLOAD_DIR,
            path=file_record.filename,
            as_attachment=True,
            download_name=file_record.original_name,
        )

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            # Проверка текущего пароля при изменении
            if new_password:
                if not current_password or not current_user.check_password(current_password):
                    flash("Неверный текущий пароль.", "danger")
                    return redirect(url_for("profile"))

                if new_password != confirm_password:
                    flash("Новые пароли не совпадают.", "danger")
                    return redirect(url_for("profile"))

                if len(new_password) < 6:
                    flash("Пароль должен содержать минимум 6 символов.", "danger")
                    return redirect(url_for("profile"))

                current_user.set_password(new_password)
                flash("Пароль успешно изменен.", "success")

            # Обновление username
            if username and username != current_user.username:
                if User.query.filter_by(username=username).first():
                    flash("Имя пользователя уже занято.", "warning")
                else:
                    current_user.username = username
                    flash("Имя пользователя обновлено.", "success")

            # Обновление email
            if email and email != current_user.email:
                if User.query.filter_by(email=email).first():
                    flash("Email уже зарегистрирован.", "warning")
                else:
                    current_user.email = email
                    flash("Email обновлен.", "success")

            db.session.commit()
            return redirect(url_for("profile"))

        return render_template("profile.html")


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

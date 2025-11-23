from __future__ import annotations

import secrets
from datetime import datetime
from functools import wraps
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
from sqlalchemy import inspect, or_, text
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


    with app.app_context():
        db.create_all()
        # Автоматическая миграция: добавление поля is_admin если его нет
        try:
            inspector = inspect(db.engine)
            # Проверяем, существует ли таблица users
            if 'users' in inspector.get_table_names():
                columns = [col['name'] for col in inspector.get_columns('users')]
                
                if 'is_admin' not in columns:
                    # Добавляем колонку is_admin
                    with db.engine.connect() as conn:
                        conn.execute(text('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0'))
                        conn.commit()
                    # Устанавливаем is_admin=False для всех существующих пользователей
                    db.session.execute(
                        text("UPDATE users SET is_admin = 0 WHERE is_admin IS NULL")
                    )
                    db.session.commit()
                
                if 'is_super_admin' not in columns:
                    # Добавляем колонку is_super_admin
                    with db.engine.connect() as conn:
                        conn.execute(text('ALTER TABLE users ADD COLUMN is_super_admin BOOLEAN DEFAULT 0'))
                        conn.commit()
                    # Устанавливаем is_super_admin=False для всех существующих пользователей
                    db.session.execute(
                        text("UPDATE users SET is_super_admin = 0 WHERE is_super_admin IS NULL")
                    )
                    db.session.commit()
                
                # Миграция для таблицы files
                if 'files' in inspector.get_table_names():
                    file_columns = [col['name'] for col in inspector.get_columns('files')]
                    
                    if 'is_deleted' not in file_columns:
                        with db.engine.connect() as conn:
                            conn.execute(text('ALTER TABLE files ADD COLUMN is_deleted BOOLEAN DEFAULT 0'))
                            conn.commit()
                        db.session.execute(
                            text("UPDATE files SET is_deleted = 0 WHERE is_deleted IS NULL")
                        )
                        db.session.commit()
                    
                    if 'deleted_at' not in file_columns:
                        with db.engine.connect() as conn:
                            conn.execute(text('ALTER TABLE files ADD COLUMN deleted_at DATETIME'))
                            conn.commit()
        except Exception as e:
            # Игнорируем ошибки миграции - возможно таблица еще не создана
            pass
        
        # Создаем директории для пользователей
        try:
            for user in User.query.all():
                user.storage_path.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Игнорируем ошибки при первом запуске, когда еще нет пользователей
            pass
        
        # Автоматическое создание супер-админа через переменные окружения
        _create_super_admin_from_env()

    return app


def _create_super_admin_from_env() -> None:
    """Создает супер-администратора из переменных окружения при первом запуске."""
    import os
    
    super_admin_username = os.environ.get("SUPER_ADMIN_USERNAME")
    super_admin_email = os.environ.get("SUPER_ADMIN_EMAIL")
    super_admin_password = os.environ.get("SUPER_ADMIN_PASSWORD")
    
    # Проверяем, есть ли уже супер-админ
    if User.query.filter_by(is_super_admin=True).first():
        return
    
    # Если все переменные заданы, создаем супер-админа
    if super_admin_username and super_admin_email and super_admin_password:
        # Проверяем, не существует ли уже пользователь
        existing_user = User.query.filter(
            (User.username == super_admin_username) | (User.email == super_admin_email)
        ).first()
        
        if not existing_user:
            admin = User(
                username=super_admin_username,
                email=super_admin_email,
                is_admin=True,
                is_super_admin=True
            )
            admin.set_password(super_admin_password)
            db.session.add(admin)
            db.session.commit()
            admin.storage_path.mkdir(parents=True, exist_ok=True)
            print(f"✅ Супер-администратор '{super_admin_username}' создан из переменных окружения.")


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
        def preview_icon(mime_type: str | None) -> str:
            if not mime_type:
                return "description"
            if mime_type.startswith("image/"):
                return "image"
            if mime_type.startswith("video/"):
                return "movie"
            if mime_type.startswith("audio/"):
                return "music_note"
            if mime_type == "application/pdf":
                return "picture_as_pdf"
            if mime_type.startswith("text/"):
                return "description"
            if "zip" in mime_type or "compressed" in mime_type:
                return "archive"
            if "spreadsheet" in mime_type or "excel" in mime_type:
                return "table"
            if "presentation" in mime_type:
                return "slideshow"
            if "word" in mime_type or "document" in mime_type:
                return "article"
            return "insert_drive_file"

        return {
            "current_year": lambda: datetime.utcnow().year,
            "preview_icon": preview_icon,
        }


def _register_routes(app: Flask) -> None:
    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        """Страница первоначальной настройки для создания супер-администратора."""
        # Проверяем, есть ли уже супер-админ
        if User.query.filter_by(is_super_admin=True).first():
            flash("Супер-администратор уже создан. Используйте форму входа.", "info")
            return redirect(url_for("login"))
        
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            
            if not username or not email or not password:
                flash("Все поля обязательны для заполнения.", "danger")
            elif password != confirm_password:
                flash("Пароли не совпадают.", "danger")
            elif len(password) < 6:
                flash("Пароль должен содержать минимум 6 символов.", "danger")
            elif User.query.filter_by(username=username).first():
                flash("Имя пользователя уже занято.", "warning")
            elif User.query.filter_by(email=email).first():
                flash("Email уже зарегистрирован.", "warning")
            else:
                admin = User(
                    username=username,
                    email=email,
                    is_admin=True,
                    is_super_admin=True
                )
                admin.set_password(password)
                db.session.add(admin)
                db.session.commit()
                admin.storage_path.mkdir(parents=True, exist_ok=True)
                flash("Супер-администратор успешно создан! Теперь вы можете войти.", "success")
                return redirect(url_for("login"))
        
        return render_template("setup.html")
    
    @app.route("/")
    def index():
        # Проверяем, есть ли супер-админ, если нет - перенаправляем на setup
        if not User.query.filter_by(is_super_admin=True).first():
            return redirect(url_for("setup"))
        
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
        # Если нет супер-админа, перенаправляем на setup
        if not User.query.filter_by(is_super_admin=True).first():
            return redirect(url_for("setup"))
        
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
        # Если нет супер-админа, перенаправляем на setup
        if not User.query.filter_by(is_super_admin=True).first():
            return redirect(url_for("setup"))
        
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

        # Базовый запрос - исключаем удаленные файлы
        query = current_user.files.filter(File.is_deleted == False)

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
            elif file_type == "application/zip":
                archive_conditions = [
                    File.mime_type.ilike("%zip%"),
                    File.mime_type.ilike("%rar%"),
                    File.mime_type.ilike("%7z%"),
                    File.mime_type.ilike("%compressed%"),
                    File.mime_type.ilike("%octet-stream%"),
                    File.original_name.ilike("%.zip"),
                    File.original_name.ilike("%.rar"),
                    File.original_name.ilike("%.7z"),
                    File.original_name.ilike("%.tar"),
                ]
                query = query.filter(or_(*archive_conditions))
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

        # Общий размер всех файлов пользователя (исключая удаленные)
        total_size = db.session.query(db.func.sum(File.file_size)).filter(
            File.user_id == current_user.id,
            File.is_deleted == False
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

            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return {
                    "status": "ok",
                    "redirect": url_for("dashboard"),
                    "successful": successful_uploads,
                    "failed": failed_uploads,
                }, 200

            return redirect(url_for("dashboard"))

        return render_template("upload.html")

    @app.route("/file/<int:file_id>")
    @login_required
    def file_detail(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)
        if file_record.is_deleted:
            abort(404)
        return render_template("download.html", file=file_record)

    @app.route("/download/<int:file_id>")
    @login_required
    def download(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)
        if file_record.is_deleted:
            abort(404)

        file_record.download_count += 1
        db.session.commit()

        return send_from_directory(
            directory=Config.UPLOAD_DIR,
            path=file_record.filename,
            as_attachment=True,
            download_name=file_record.original_name,
        )

    @app.route("/preview/<int:file_id>")
    @login_required
    def preview_file(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)
        if file_record.is_deleted:
            abort(404)

        if not file_record.mime_type or not file_record.mime_type.startswith("image/"):
            abort(404)

        return send_from_directory(
            directory=Config.UPLOAD_DIR,
            path=file_record.filename,
            as_attachment=False,
            mimetype=file_record.mime_type,
        )

    @app.route("/delete/<int:file_id>", methods=["POST"])
    @login_required
    def delete(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)
        
        if file_record.is_deleted:
            abort(404)

        # Помечаем файл как удаленный вместо физического удаления
        file_record.is_deleted = True
        file_record.deleted_at = datetime.utcnow()
        db.session.commit()
        flash("Файл перемещен в корзину.", "info")
        return redirect(url_for("dashboard"))

    @app.route("/files/bulk-delete", methods=["POST"])
    @login_required
    def bulk_delete():
        action = request.form.get("action", "delete_selected")
        files_to_delete: list[File] = []

        if action == "delete_all":
            files_to_delete = current_user.files.filter(File.is_deleted == False).order_by(File.uploaded_at.desc()).all()
            if not files_to_delete:
                flash("Нет файлов для удаления.", "info")
                return redirect(url_for("dashboard"))
        else:
            selected_ids = request.form.getlist("file_ids")
            if not selected_ids:
                flash("Выберите хотя бы один файл.", "warning")
                return redirect(url_for("dashboard"))

            try:
                selected_ids = [int(file_id) for file_id in selected_ids]
            except ValueError:
                flash("Некорректный список файлов.", "danger")
                return redirect(url_for("dashboard"))

            files_to_delete = (
                File.query.filter(File.id.in_(selected_ids), File.user_id == current_user.id, File.is_deleted == False)
                .order_by(File.uploaded_at.desc())
                .all()
            )

            if not files_to_delete:
                flash("Не удалось найти выбранные файлы.", "warning")
                return redirect(url_for("dashboard"))

        deleted_count = 0
        for file_record in files_to_delete:
            if not file_record.is_deleted:
                file_record.is_deleted = True
                file_record.deleted_at = datetime.utcnow()
                deleted_count += 1

        db.session.commit()

        if action == "delete_all":
            flash(f"Файлы перемещены в корзину ({deleted_count}).", "info")
        else:
            flash(f"Файлы перемещены в корзину ({deleted_count}).", "info")

        return redirect(url_for("dashboard"))

    @app.route("/file/<int:file_id>/share", methods=["POST"])
    @login_required
    def toggle_share(file_id: int):
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)
        if file_record.is_deleted:
            abort(404)

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
        file_record = File.query.filter_by(share_token=token, is_public=True, is_deleted=False).first_or_404()
        return render_template("share.html", file=file_record)

    @app.route("/share/<token>/download")
    def share_download(token: str):
        file_record = File.query.filter_by(share_token=token, is_public=True, is_deleted=False).first_or_404()
        
        file_record.download_count += 1
        db.session.commit()

        return send_from_directory(
            directory=Config.UPLOAD_DIR,
            path=file_record.filename,
            as_attachment=True,
            download_name=file_record.original_name,
        )
    
    @app.route("/trash")
    @login_required
    def trash():
        """Страница корзины с удаленными файлами."""
        search_query = request.args.get("search", "").strip()
        sort_by = request.args.get("sort", "deleted_desc")
        page = request.args.get("page", 1, type=int)
        per_page = 20
        
        # Запрос удаленных файлов пользователя
        query = current_user.files.filter(File.is_deleted == True)
        
        # Поиск по имени файла
        if search_query:
            query = query.filter(File.original_name.ilike(f"%{search_query}%"))
        
        # Сортировка
        if sort_by == "name_asc":
            query = query.order_by(File.original_name.asc())
        elif sort_by == "name_desc":
            query = query.order_by(File.original_name.desc())
        elif sort_by == "size_asc":
            query = query.order_by(File.file_size.asc())
        elif sort_by == "size_desc":
            query = query.order_by(File.file_size.desc())
        elif sort_by == "deleted_asc":
            query = query.order_by(File.deleted_at.asc())
        else:  # deleted_desc по умолчанию
            query = query.order_by(File.deleted_at.desc())
        
        # Пагинация
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        deleted_files = pagination.items
        
        return render_template(
            "trash.html",
            files=deleted_files,
            pagination=pagination,
            search_query=search_query,
            sort_by=sort_by,
        )
    
    @app.route("/trash/<int:file_id>/restore", methods=["POST"])
    @login_required
    def restore_file(file_id: int):
        """Восстановление файла из корзины."""
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)
        if not file_record.is_deleted:
            flash("Файл не находится в корзине.", "warning")
            return redirect(url_for("trash"))
        
        file_record.is_deleted = False
        file_record.deleted_at = None
        db.session.commit()
        flash(f"Файл '{file_record.original_name}' восстановлен.", "success")
        return redirect(url_for("trash"))
    
    @app.route("/trash/<int:file_id>/permanent-delete", methods=["POST"])
    @login_required
    def permanent_delete(file_id: int):
        """Окончательное удаление файла из корзины."""
        file_record = File.query.get_or_404(file_id)
        if file_record.owner != current_user:
            abort(403)
        if not file_record.is_deleted:
            flash("Файл не находится в корзине.", "warning")
            return redirect(url_for("trash"))
        
        original_name = file_record.original_name
        _remove_file_from_storage(file_record)
        db.session.delete(file_record)
        db.session.commit()
        flash(f"Файл '{original_name}' окончательно удален.", "info")
        return redirect(url_for("trash"))
    
    @app.route("/trash/bulk-restore", methods=["POST"])
    @login_required
    def bulk_restore():
        """Массовое восстановление файлов."""
        selected_ids = request.form.getlist("file_ids")
        if not selected_ids:
            flash("Выберите хотя бы один файл.", "warning")
            return redirect(url_for("trash"))
        
        try:
            selected_ids = [int(file_id) for file_id in selected_ids]
        except ValueError:
            flash("Некорректный список файлов.", "danger")
            return redirect(url_for("trash"))
        
        files_to_restore = (
            File.query.filter(File.id.in_(selected_ids), File.user_id == current_user.id, File.is_deleted == True)
            .all()
        )
        
        if not files_to_restore:
            flash("Не удалось найти выбранные файлы.", "warning")
            return redirect(url_for("trash"))
        
        restored_count = 0
        for file_record in files_to_restore:
            file_record.is_deleted = False
            file_record.deleted_at = None
            restored_count += 1
        
        db.session.commit()
        flash(f"Восстановлено файлов: {restored_count}.", "success")
        return redirect(url_for("trash"))
    
    @app.route("/trash/bulk-permanent-delete", methods=["POST"])
    @login_required
    def bulk_permanent_delete():
        """Массовое окончательное удаление файлов."""
        selected_ids = request.form.getlist("file_ids")
        if not selected_ids:
            flash("Выберите хотя бы один файл.", "warning")
            return redirect(url_for("trash"))
        
        try:
            selected_ids = [int(file_id) for file_id in selected_ids]
        except ValueError:
            flash("Некорректный список файлов.", "danger")
            return redirect(url_for("trash"))
        
        files_to_delete = (
            File.query.filter(File.id.in_(selected_ids), File.user_id == current_user.id, File.is_deleted == True)
            .all()
        )
        
        if not files_to_delete:
            flash("Не удалось найти выбранные файлы.", "warning")
            return redirect(url_for("trash"))
        
        deleted_count = 0
        for file_record in files_to_delete:
            _remove_file_from_storage(file_record)
            db.session.delete(file_record)
            deleted_count += 1
        
        db.session.commit()
        flash(f"Окончательно удалено файлов: {deleted_count}.", "info")
        return redirect(url_for("trash"))
    
    @app.route("/trash/empty", methods=["POST"])
    @login_required
    def empty_trash():
        """Очистка всей корзины."""
        files_to_delete = current_user.files.filter(File.is_deleted == True).all()
        
        if not files_to_delete:
            flash("Корзина уже пуста.", "info")
            return redirect(url_for("trash"))
        
        deleted_count = 0
        for file_record in files_to_delete:
            _remove_file_from_storage(file_record)
            db.session.delete(file_record)
            deleted_count += 1
        
        db.session.commit()
        flash(f"Корзина очищена. Удалено файлов: {deleted_count}.", "info")
        return redirect(url_for("trash"))

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

    # Admin routes
    @app.route("/admin")
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            abort(403)
        
        # Статистика
        total_users = User.query.count()
        total_files = File.query.count()
        total_size = db.session.query(db.func.sum(File.file_size)).scalar() or 0
        admin_count = User.query.filter_by(is_admin=True).count()
        
        # Последние пользователи
        recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
        
        # Последние файлы
        recent_files = File.query.order_by(File.uploaded_at.desc()).limit(10).all()
        
        # Статистика по типам файлов
        file_types_stats = (
            db.session.query(
                db.func.count(File.id).label('count'),
                db.func.sum(File.file_size).label('total_size'),
                File.mime_type
            )
            .group_by(File.mime_type)
            .order_by(db.func.count(File.id).desc())
            .limit(10)
            .all()
        )
        
        return render_template(
            "admin/dashboard.html",
            total_users=total_users,
            total_files=total_files,
            total_size=total_size,
            admin_count=admin_count,
            recent_users=recent_users,
            recent_files=recent_files,
            file_types_stats=file_types_stats,
        )

    @app.route("/admin/users")
    @login_required
    def admin_users():
        if not current_user.is_admin:
            abort(403)
        
        search_query = request.args.get("search", "").strip()
        page = request.args.get("page", 1, type=int)
        per_page = 20
        
        query = User.query
        
        if search_query:
            query = query.filter(
                or_(
                    User.username.ilike(f"%{search_query}%"),
                    User.email.ilike(f"%{search_query}%")
                )
            )
        
        query = query.order_by(User.created_at.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        users = pagination.items
        
        # Добавляем статистику для каждого пользователя
        for user in users:
            user.file_count = user.files.count()
            user.total_size = db.session.query(db.func.sum(File.file_size)).filter(
                File.user_id == user.id
            ).scalar() or 0
        
        return render_template(
            "admin/users.html",
            users=users,
            pagination=pagination,
            search_query=search_query,
        )

    @app.route("/admin/users/<int:user_id>/toggle-admin", methods=["POST"])
    @login_required
    def admin_toggle_admin(user_id: int):
        if not current_user.is_admin:
            abort(403)
        
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash("Вы не можете изменить свои права администратора.", "warning")
            return redirect(url_for("admin_users"))
        
        # Защита супер-админа от снятия прав
        if user.is_super_admin:
            flash("Нельзя изменить права супер-администратора.", "danger")
            return redirect(url_for("admin_users"))
        
        user.is_admin = not user.is_admin
        db.session.commit()
        
        status = "назначен администратором" if user.is_admin else "лишен прав администратора"
        flash(f"Пользователь {user.username} {status}.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    def admin_delete_user(user_id: int):
        if not current_user.is_admin:
            abort(403)
        
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash("Вы не можете удалить свой аккаунт.", "warning")
            return redirect(url_for("admin_users"))
        
        # Защита супер-админа от удаления
        if user.is_super_admin:
            flash("Нельзя удалить супер-администратора.", "danger")
            return redirect(url_for("admin_users"))
        
        username = user.username
        # Удаление всех файлов пользователя
        for file_record in user.files:
            _remove_file_from_storage(file_record)
        
        db.session.delete(user)
        db.session.commit()
        
        flash(f"Пользователь {username} и все его файлы удалены.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/files")
    @login_required
    def admin_files():
        if not current_user.is_admin:
            abort(403)
        
        search_query = request.args.get("search", "").strip()
        file_type = request.args.get("type", "")
        user_id = request.args.get("user_id", type=int)
        sort_by = request.args.get("sort", "date_desc")
        page = request.args.get("page", 1, type=int)
        per_page = 50
        
        query = File.query
        
        if search_query:
            query = query.filter(File.original_name.ilike(f"%{search_query}%"))
        
        if file_type:
            if file_type == "image":
                query = query.filter(File.mime_type.like("image/%"))
            elif file_type == "video":
                query = query.filter(File.mime_type.like("video/%"))
            elif file_type == "audio":
                query = query.filter(File.mime_type.like("audio/%"))
            else:
                query = query.filter(File.mime_type.like(f"%{file_type}%"))
        
        if user_id:
            query = query.filter(File.user_id == user_id)
        
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
        else:
            query = query.order_by(File.uploaded_at.desc())
        
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        files = pagination.items
        
        return render_template(
            "admin/files.html",
            files=files,
            pagination=pagination,
            search_query=search_query,
            file_type=file_type,
            user_id=user_id,
            sort_by=sort_by,
        )

    @app.route("/admin/files/<int:file_id>/delete", methods=["POST"])
    @login_required
    def admin_delete_file(file_id: int):
        if not current_user.is_admin:
            abort(403)
        
        file_record = File.query.get_or_404(file_id)
        original_name = file_record.original_name
        _remove_file_from_storage(file_record)
        db.session.delete(file_record)
        db.session.commit()
        
        flash(f"Файл {original_name} удален.", "success")
        return redirect(url_for("admin_files"))


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
    @app.cli.command("create-super-admin")
    def create_super_admin() -> None:
        """Создать супер-администратора интерактивно через CLI."""
        import getpass
        
        # Проверяем, есть ли уже супер-админ
        existing_super_admin = User.query.filter_by(is_super_admin=True).first()
        if existing_super_admin:
            print(f"⚠️  Супер-администратор уже существует: {existing_super_admin.username}")
            response = input("Создать еще одного? (y/N): ").strip().lower()
            if response != 'y':
                print("Отменено.")
                return
        
        print("=" * 50)
        print("Создание супер-администратора")
        print("=" * 50)
        
        username = input("Имя пользователя: ").strip()
        email = input("Email: ").strip().lower()
        password = getpass.getpass("Пароль: ")
        confirm_password = getpass.getpass("Подтвердите пароль: ")

        if not username or not email or not password:
            print("\n❌ Ошибка: Все поля обязательны.")
            return
        
        if password != confirm_password:
            print("\n❌ Ошибка: Пароли не совпадают.")
            return
        
        if len(password) < 6:
            print("\n❌ Ошибка: Пароль должен содержать минимум 6 символов.")
            return

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            print(f"\n❌ Ошибка: Пользователь с именем '{username}' или email '{email}' уже существует.")
            return

        try:
            user = User(username=username, email=email, is_admin=True, is_super_admin=True)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            user.storage_path.mkdir(parents=True, exist_ok=True)
            print(f"\n✅ Супер-администратор '{username}' успешно создан!")
            print(f"   Email: {email}")
            print(f"   Права: Супер-администратор (нельзя снять права или удалить)")
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Ошибка при создании супер-администратора: {e}")
    
    @app.cli.command("create-admin")
    def create_admin() -> None:
        """Создать обычного администратора (устаревшая команда, используйте create-super-admin)."""
        print("⚠️  Эта команда устарела. Используйте 'flask create-super-admin' для создания супер-администратора.")
        print("   Или используйте веб-интерфейс: откройте /setup в браузере.")


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def _remove_file_from_storage(file_record: File) -> None:
    file_path = Config.UPLOAD_DIR / file_record.filename
    if file_path.exists():
        file_path.unlink()


app = create_app()


@app.shell_context_processor
def _make_shell_context():
    return {"db": db, "User": User, "File": File, "Path": Path}


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=2222)

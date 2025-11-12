import os
from pathlib import Path


class Config:
    """Base configuration for the file hosting application."""

    BASE_DIR = Path(__file__).resolve().parent
    INSTANCE_DIR = BASE_DIR / "instance"
    UPLOAD_DIR = BASE_DIR / "uploads"
    USER_STORAGE_DIR = BASE_DIR / "users"

    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key")
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URI")
        or f"sqlite:///{(INSTANCE_DIR / 'database.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024
    SITE_NAME = "Облачное хранилище"

    ALLOWED_EXTENSIONS = {
        "txt",
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "zip",
        "rar",
        "7z",
        "tar",
        "gz",
        "mp3",
        "mp4",
        "csv",
        "doc",
        "docx",
        "ppt",
        "pptx",
        "xls",
        "xlsx",
    }


def ensure_directories():
    for directory in [
        Config.INSTANCE_DIR,
        Config.UPLOAD_DIR,
        Config.USER_STORAGE_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)


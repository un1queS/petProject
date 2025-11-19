from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    files = db.relationship(
        "File",
        back_populates="owner",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def __repr__(self) -> str:  
        return f"<User {self.username}>"

    @property
    def storage_path(self) -> Path:
        from config import Config

        return Config.USER_STORAGE_DIR / self.username

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    original_name = db.Column(db.String(256), nullable=False)
    mime_type = db.Column(db.String(128))
    file_size = db.Column(db.Integer, nullable=False, default=0)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    download_count = db.Column(db.Integer, default=0, nullable=False)
    description = db.Column(db.Text)
    share_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    is_public = db.Column(db.Boolean, default=False, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    owner = db.relationship("User", back_populates="files")

    def __repr__(self) -> str:  
        return f"<File {self.original_name}>"

    @property
    def storage_path(self) -> Path:
        from config import Config

        return Config.UPLOAD_DIR / self.filename

    def to_dict(self) -> dict[str, Optional[str]]:
        return {
            "id": self.id,
            "filename": self.filename,
            "original_name": self.original_name,
            "mime_type": self.mime_type,
            "file_size": self.file_size,
            "uploaded_at": self.uploaded_at.isoformat(),
            "download_count": self.download_count,
            "description": self.description,
            "user_id": self.user_id,
        }


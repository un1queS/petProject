from app import app, db
from models import User
import getpass

with app.app_context():
    print("=" * 50)
    print("Создание администратора")
    print("=" * 50)
    
    username = input("Имя пользователя: ").strip()
    email = input("Email: ").strip()
    password = getpass.getpass("Пароль: ")
    
    if not username or not email or not password:
        print("\n❌ Ошибка: Все поля обязательны.")
        exit(1)
    
    # Проверяем, существует ли пользователь
    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()
    
    if existing_user:
        print(f"\n❌ Ошибка: Пользователь с именем '{username}' или email '{email}' уже существует.")
        exit(1)
    
    # Создаем администратора
    admin = User(username=username, email=email, is_admin=True)
    admin.set_password(password)
    
    try:
        db.session.add(admin)
        db.session.commit()
        admin.storage_path.mkdir(parents=True, exist_ok=True)
        print(f"\n✅ Администратор '{username}' успешно создан!")
        print(f"   Email: {email}")
        print(f"   Права: Администратор")
    except Exception as e:
        db.session.rollback()
        print(f"\n❌ Ошибка при создании администратора: {e}")
        exit(1)


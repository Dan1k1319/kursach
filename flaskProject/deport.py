from app import  db, User, UserProfile

with app.app_context():
    # Получаем все записи из таблицы User
    users = User.query.all()
    for user in users:
        print(user.id, user.username, user.email)

    # Получаем все записи из таблицы UserProfile
    profiles = UserProfile.query.all()
    for profile in profiles:
        print(profile.id, profile.user_id, profile.bio)
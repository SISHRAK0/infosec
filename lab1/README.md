# Лабораторная работа 1: защищённый REST API с интеграцией в CI/CD

## API

| Метод | Путь | Доступ | Описание |
|-------|------|--------|----------|
| POST | `/auth/register` | все | регистрация пользователя |
| POST | `/auth/login` | все | вход, возвращает JWT |
| GET | `/api/data` | только с JWT | список пользователей |

### Регистрация

```bash
curl -X POST http://localhost:5001/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "password123"}'
# 201 {"id": 1, "username": "alice"}
```

Пароль от 8 до 72 байт. Если логин уже занят, возвращается `409`.

### Вход

```bash
curl -X POST http://localhost:5001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "password123"}'
# 200 {"access_token": "eyJhbGciOi..."}
```

При неверном логине или пароле возвращается `401`.

### Получение данных

```bash
curl http://localhost:5001/api/data -H "Authorization: Bearer <access_token>"
# 200 {"users": [{"id": 1, "username": "alice"}]}

curl http://localhost:5001/api/data
# 401 {"error": "Missing token"}
```

## Меры защиты

### SQL-инъекции

Все запросы параметризованные: в тексте SQL стоят плейсхолдеры `?`, а значения
передаются отдельно, например:

```python
db.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
```

Драйвер SQLite передаёт значение как данные, а не как часть запроса, поэтому
ввод вида `' OR '1'='1` просто ищется как логин и ничего не находит.

### XSS

Все пользовательские данные экранируются функцией `markupsafe.escape` перед отдачей
в ответе. Например, логин `<script>alert(1)</script>` вернётся как
`&lt;script&gt;alert(1)&lt;/script&gt;` и в браузере не выполнится.

### Аутентификация

- **Хранение паролей.** Пароли хэшируются bcrypt со случайной солью, в базе хранится
  только хэш. bcrypt намеренно медленный, поэтому перебор паролей по украденной базе
  обходится дорого.
- **JWT.** После успешного входа выдаётся токен HS256, в нём id пользователя (`sub`),
  время выдачи (`iat`) и срок действия (`exp`, 30 минут). Ключ подписи берётся
  из переменной окружения `JWT_SECRET`, в коде его нет.
- **Middleware.** Декоратор `token_required` стоит на защищённых эндпоинтах.
  Он проверяет заголовок `Authorization: Bearer <token>`, подпись токена и срок действия.
  Разрешён только алгоритм HS256, поэтому поддельный токен с `alg: none` не пройдёт.
  Если токена нет или он невалиден, возвращается `401`.

## CI/CD

Файл `.github/workflows/ci.yml`. Запускается на каждый push и pull request:

1. `pytest` — тесты API: вход, доступ без токена, SQL-инъекция, XSS.
2. **SAST** — `bandit app.py`, статический анализ кода на уязвимости.
3. **SCA** — `pip-audit -r requirements.txt`, проверка зависимостей по базе известных уязвимостей.

Если любая проверка находит проблему, pipeline падает.



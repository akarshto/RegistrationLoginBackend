# RegistrationLoginBackend

Spring Boot backend for the Registration & Login system.

## Prerequisites

- Java 17+
- Maven
- MySQL80 running locally on `localhost:3306`

## Configure

Edit `src/main/resources/application.properties`:
- `spring.datasource.username` / `spring.datasource.password` — your local MySQL credentials.
- `app.jwt.secret` — replace with your own long random secret before any real deployment.

The schema (`registration_login_db`, `users`, `jwt_token`) is created automatically on startup via `spring.jpa.hibernate.ddl-auto=update`.

## Run

```bash
mvn spring-boot:run
```

Runs on `http://localhost:8080`.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/registration` | public | Create a user (BCrypt-hashed password) |
| POST | `/api/login` | public | Verify credentials, issue JWT as HttpOnly cookie |
| GET | `/api/user/me` | cookie | Return the authenticated user's profile |
| POST | `/api/logout` | cookie | Invalidate the token and clear the cookie |

## Security notes

- Passwords are hashed with `BCryptPasswordEncoder` (`SecurityConfig`) — never MD5/SHA/Base64/plaintext.
- JWTs are signed HS256 (`JwtService`), expire in exactly 1 hour, and are only ever transmitted as an `HttpOnly` cookie (`AuthController`) — never in a JSON body or header the frontend could read into `localStorage`.
- Each login also inserts a row into `jwt_token`; `AuthenticationService.validateSessionAndGetUser` checks both the JWT signature/expiry *and* that row, so logout can immediately revoke a session.
- CORS (`SecurityConfig.corsConfigurationSource`) allows exactly `http://localhost:3000` with credentials — never a wildcard, since wildcard origins are incompatible with credentialed cookies.

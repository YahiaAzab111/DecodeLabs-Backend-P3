# DecodeLabs Backend — Project 3: Secure Authentication System

**Domain:** Backend Development  
**Stack:** Python + Flask + SQLite + JWT + bcrypt  
**Internship Batch:** 2026

---

## What This Project Does

This project adds a full authentication layer to the backend. Users can register with a hashed password, log in to receive a JWT, and use that token to access protected routes. Unauthenticated requests are rejected with a 401 Unauthorized response.

The system also implements **role-based access control** — admin users can access endpoints that regular users cannot.

---

## File Structure

```
DecodeLabs-Backend-P3/
├── app.py               # Server entry point
├── database.py          # Schema with users table
├── middleware.py        # JWT verification decorators
├── auth_routes.py       # /auth/register and /auth/login
├── protected_routes.py  # /profile, /dashboard, /admin/users
├── requirements.txt
└── .gitignore
```

---

## Authentication Flow

```
REGISTER                          LOGIN
────────                          ─────
Client sends:                     Client sends:
  username, email, password         email, password
        │                                 │
bcrypt hashes password            Fetch user by email
        │                                 │
Store hash in DB                  bcrypt.checkpw()
        │                                 │
Return 201 Created                Sign JWT (24h expiry)
                                          │
                                   Return token

PROTECTED REQUEST
─────────────────
Client sends:
  Authorization: Bearer <token>
        │
Decode + verify JWT
        │
  Valid → run route
  Expired → 401
  Invalid → 401
```

---

## API Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/auth/register` | No | Create new account |
| POST | `/auth/login` | No | Login, receive JWT |
| GET | `/profile` | Yes (any user) | View own profile |
| GET | `/dashboard` | Yes (any user) | User dashboard |
| GET | `/admin/users` | Yes (admin only) | List all users |

---

## How to Run

```bash
pip install -r requirements.txt
python app.py
```

---

## Example Usage

```bash
# Register
curl -X POST http://127.0.0.1:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "yahia", "email": "yahia@test.com", "password": "secure123"}'

# Login — copy the token from the response
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "yahia@test.com", "password": "secure123"}'

# Access protected route with token
curl http://127.0.0.1:5000/profile \
  -H "Authorization: Bearer <your_token_here>"

# Try without token — returns 401
curl http://127.0.0.1:5000/profile
```

---

## Security Concepts Demonstrated

- **Password hashing** — bcrypt with automatic salt generation; same password always produces different hashes
- **JWT authentication** — stateless tokens signed with HS256; no server-side session storage needed
- **Token expiration** — tokens expire after 24 hours, forcing re-login
- **Generic auth errors** — login returns the same message for wrong email or wrong password (prevents user enumeration)
- **Role-based access control** — `admin_required` decorator restricts admin routes
- **Middleware pattern** — `@token_required` decorator reusable on any route

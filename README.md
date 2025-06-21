# User Management API (Go + Gin + MongoDB)

ระบบจัดการผู้ใช้งาน พร้อมระบบ Authentication, JWT Token, Soft/Hard Delete และ Reset Password

---

## Features

- Register / Login / Logout (JWT)
- Get / Update / Delete user
- Soft Delete และ Hard Delete
- JWT TokenVersion ตรวจสอบ token invalidate
- Request reset password พร้อม blacklist token
- MongoDB backend

---

## Technologies

- Go (Gin Framework)
- MongoDB (with official driver)
- JWT (github.com/golang-jwt/jwt/v5)
- Bcrypt (password hashing)

---
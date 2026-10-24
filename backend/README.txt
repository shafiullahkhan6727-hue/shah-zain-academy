SHAH ZAIN ACADEMY BACKEND

Start locally:
cd ~/shahzain-academy
python backend/app.py

Health check:
http://127.0.0.1:5000/api/health

IMPORTANT SECURITY LIMITATIONS:
- This backend is an initial local prototype, not a production payment system.
- No EasyPaisa/JazzCash merchant API is integrated.
- Orders stay PENDING; this code has no verification/admin approval endpoint.
- Do not deploy publicly as-is.
- Store private PDFs only in private_materials, not in the public website folder.
- Do not place payment PINs, OTPs or banking passwords in this website.
- Before production, add HTTPS, secure cookie settings, CSRF protection,
  admin-only payment approval, rate limiting, backups, and payment gateway webhooks.

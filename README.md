# Fududeeye Online — Production hardening + Seller Approval 24H

This package is prepared for GitHub / Render as one Node/Express web service.

## Render
- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Health check: `/health`

## Seller approval (24 hours)
- New sellers start as `pending` and cannot log in until approved.
- The server records the application time and a 24-hour deadline.
- Pending applications are automatically marked `expired` after the deadline.
- Admin can approve or reject pending applications, and can manually approve an expired application.
- Rejection reason and decision time are stored.

## Security improvements in this version
- Production startup refuses placeholder secrets for JWT, admin password, and payment webhook.
- Authentication and registration endpoints have rate limiting.
- JSON request body limit reduced to 1 MB.
- Seller approval and account activation are kept synchronized.
- Approval actions are written to audit logs.

## Environment variables
Set a strong `ADMIN_PASSWORD` in Render. Render can generate `JWT_SECRET` and `PAYMENT_WEBHOOK_SECRET`.

## Important: database
The current app still uses SQLite. For a high-traffic production deployment, migrate to PostgreSQL and attach persistent storage/backups before launch.

## Payments
Real Zaad/eDahab automatic payment verification is not included without an official provider API/webhook. Do not use fake SMS/OTP or scraping.

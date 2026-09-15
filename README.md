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


Login redesign: the login section now has a polished green/white responsive layout with Forgot Password, Diiwaangeli Bakhaar, and quick-access buttons.


## Store registration
Seller registration now collects owner name/phone/password/gender, store name/type, products sold, city, neighborhood, address, GPS location, opening hours, delivery availability, and description. The submitted application remains pending for admin approval.

## Additional hardening in this update
- Seller registration now stores optional business buyer phone, store size, owner photo, and ID/passport photo when supplied.
- Removed duplicate store-type fields from the registration form.
- Added input limits/validation for seller/product data and image payloads.
- Product creation now requires an approved/active seller store.
- Order stock decrement is atomic, preventing stock from going negative under concurrent orders.
- Seller order status changes follow a basic valid transition flow.
- Added a generic server error response instead of exposing internal errors to users.


### Account phone uniqueness
- One normalized phone number can have only one account.
- Customer, Seller and Admin registrations all reject an already-registered phone.
- Somalia formats such as 063xxxxxxx and +25263xxxxxxx normalize to the same account phone, preventing duplicate accounts.
- The users.phone database UNIQUE constraint is the final protection against duplicate accounts.

## Account Bakhaar Tusaale ah
Nooca V13 waxa ku jira account bakhaar oo tusaale ah oo si automatic ah loo abuuro marka database-ku markii ugu horreysay bilaabmo:

- Magaca: **Bakhaar Tusaale**
- Magaca bakhaarka: **Fududeeye Raashin**
- Telefoon: **0637000000**
- Password: **Demo1234**
- Magaalada: **Hargeysa**
- Xaafadda: **26 June**
- Xaaladda: **La ansixiyey**
- Delivery: **Haa**

Waxaa horay loogu sii daray 8 alaabood oo raashin ah oo leh qiime iyo stock tusaale ah. Account-kan waxaa loogu talagalay demo/testing oo keliya, waxaana Admin-ka laga beddeli karaa ama laga tirtiri karaa.

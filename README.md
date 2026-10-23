# ACADEXA — Faculty Performance & Academic Activity Dashboard

ACADEXA is a MERN academic workspace with three roles and an approval-first access model. This enhanced source version implements HOD registration approved by Admin, Faculty registration approved by the assigned department HOD, faculty-entered academic records, HOD record review, role-limited messaging, in-app notifications and Admin audit events. Dashboards start empty and use persisted records rather than seeded sample statistics.

## Requirements
- Node.js 18+
- MongoDB local instance or MongoDB Atlas

## Setup (Windows PowerShell)
1. Open this folder in Terminal.
2. Run `npm run setup`.
3. Copy `server/.env.example` to `server/.env`.
4. Set `MONGO_URI`, a long random `JWT_SECRET`, and a private `ADMIN_SETUP_KEY` in `server/.env`.
5. Run `npm run dev`.
6. Open `http://localhost:5173`.

No demo accounts or sample academic records are created. Create the first Admin using the protected setup endpoint one time:

`POST http://localhost:5000/api/auth/setup-admin`

Header: `x-setup-key: <the ADMIN_SETUP_KEY from server/.env>`

JSON body example (replace with real institutional details):

```json
{"name":"Institution Admin","email":"admin@yourinstitution.edu","employeeId":"ADMIN-001","institution":"Your Institution","department":"Administration","designation":"System Administrator","password":"use-a-unique-password-at-least-12-characters"}
```

After the Admin account is created, remove or rotate `ADMIN_SETUP_KEY` and restart the server. The endpoint will not create a second Admin. HODs register through the UI and await Admin approval; Faculty register and await their matching institution + department HOD approval.

## Features
- Role-based authentication (JWT) and bcrypt password hashing
- Public registration for HOD and Faculty only; no public Admin registration
- Pending/approved/rejected access requests and reviewer notes
- Faculty-owned academic activity drafts and submissions
- Department-scoped HOD review and status feedback
- Authorized internal messaging and in-app notifications
- Minimal Admin HOD approvals and audit trail
- Responsive white/purple interface and empty states for new users

## Notes
This source is a safe, runnable foundation built from the supplied ACADEXA package metadata and README because the uploaded ZIP did not include the original `client/src` or `server/src` source. Existing compiled `client/dist` files are retained in the archive as a reference, but the Vite app uses the new source under `client/src`. Verify institutional policies and test with a non-production database before deployment. For production, use HTTPS, rotate secrets, configure strict CORS, back up MongoDB and review security requirements.

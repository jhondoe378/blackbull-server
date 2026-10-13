# Blackbull account server

This server handles the parts of Blackbull that must not run in a browser:

- sending a one-time code by text message to a real phone number,
- creating accounts (one account per phone number, unique usernames),
- passwords stored safely (scrypt, never in plain text),
- logins, sessions and lockouts after wrong passwords,
- limits on codes and sign-ups, so one person can't flood it.

It uses only built-in Node.js modules, so there is nothing to install.
Requires Node.js 18.17 or newer.

## Run it on your computer (test mode)

    npm test
    DEV_EXPOSE_CODES=1 npm start

In test mode there is no real SMS. The code is printed in the console,
and with `DEV_EXPOSE_CODES=1` it is also returned to the caller. Never
turn that on in production.

## Put it online

1. Get a server or hosting service that runs Node.js (for example Render,
   Railway, Fly.io, or a small VPS). Use HTTPS. Most hosts do this for you.
2. Create a Twilio account, buy a phone number that can send SMS, and copy
   the Account SID, Auth Token and the number into the environment settings.
   Use `.env.example` as the list of settings.
3. Set `DATA_DIR` to a folder on a disk that survives restarts, and back it up.
4. Set `CORS_ORIGIN` to the exact address where the Blackbull app is hosted.
5. Start with `npm start`. In production the server refuses to start without
   an SMS provider.

## Endpoints

| Method | Path | What it does |
|---|---|---|
| POST | /api/auth/request-code | `{phone}` sends a 6-digit code by SMS |
| POST | /api/auth/verify-code | `{phone, code}` returns a short-lived `signupToken` |
| POST | /api/auth/signup | `{signupToken, username, name, password}` creates the account and logs in |
| POST | /api/auth/login | `{username, password}` returns a session `token` |
| POST | /api/auth/logout | ends the session (send `Authorization: Bearer <token>`) |
| GET | /api/me | returns the logged-in user |

Limits built in:

- one code per minute per number, five codes per hour per number, 20 requests
  per hour per address,
- a code works for 5 minutes, and is burned after 5 wrong tries,
- a sign-up token works for 10 minutes,
- five wrong passwords lock that account for 5 minutes,
- a device or network can't flood the sign-up step.

## Important notes

- **Keep the database file safe.** It holds accounts. Back it up.
- **If the file is damaged, the server refuses to start** rather than
  losing data. Restore a backup in that case.
- **This is one server process.** It keeps data in one file, so run only one
  copy. Growing to many users needs a proper database (PostgreSQL), which
  can be added later without changing the endpoints.
- **Sending SMS costs money** per message through Twilio. The limits above keep
  that cost under control.
- **Connecting the app:** the Blackbull web page still stores its data in its
  current online storage. Moving the app's sign-in to these endpoints is the
  next step, and it changes the sign-up and login screens to call this server.

# krabo-gold API Gateway

## Auth flow

1. `POST /api/auth/request-otp`
2. `POST /api/auth/verify-otp`
   - Existing completed user: returns access token and refresh cookies.
   - New/incomplete user: returns `requiresRegistration: true` and a short-lived `registrationToken`.
3. `POST /api/auth/register`
   - Accepts `registrationToken`, `name`, optional `nationalCode`, optional `email`.
   - Creates/completes the user and returns access token + refresh cookies.

## User/Profile APIs

- `GET /api/users/me`
- `PUT /api/users/me`
- `GET /api/users/me/addresses`
- `POST /api/users/me/addresses`
- `GET /api/users/me/addresses/{addressId}`
- `PUT /api/users/me/addresses/{addressId}`
- `DELETE /api/users/me/addresses/{addressId}`

## Dynamic proxy

`/api/proxy/{service}/{path}` remains dynamic and authenticated.
The Gateway extracts the authenticated user id from JWT and sends it to downstream services as:

- `USER_ID`
- `X-User-Id`
- `X-Gateway-User-Id`

The upstream HTTP status, content type, safe response headers and response body are returned to the frontend. Backend timeout returns `504`; connectivity errors return `502`.

## Database

Migration `20261025143000_AddUserAddresses` adds the `UserAddresses` table. Startup already runs `Database.MigrateAsync()`, so the migration is applied automatically when the application starts.

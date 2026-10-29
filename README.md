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

## Anonymous GET dynamic proxy

The original authenticated proxy remains unchanged:

- `GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS /api/proxy/{service}/{**path}` - JWT required.

An additional endpoint accepts **GET only**, without an access token:

- `GET /api/proxy-public/{service}/{**path}` - no JWT required.

For example:

```http
GET /api/proxy-public/django/api/wallet
```

Given backend configuration `BaseUrl = https://python.krabo.gold` and
`AllowedPathPrefixes = ["api/"]`, this forwards to:

```http
GET https://python.krabo.gold/api/wallet
```

The request still passes through the same backend config validation, HTTPS check,
`AllowedPathPrefixes` check, global Redis rate limiting, restricted request/response
headers, response size limit, and upstream timeout handling. The backend's status,
content type, and response body are returned to the client.

Gateway-to-backend service authentication (`X-Gateway-Service-Token`) is retained,
but user headers (`USER_ID`, `X-User-Id`, `X-Gateway-User-Id`,
`X-Gateway-User-Mobile`) are **not sent** for anonymous requests.

**Security warning:** With `AllowedPathPrefixes = ["api/"]`, ALL GET routes
under `api/` for that backend become callable without JWT through this new
endpoint, including any sensitive GET routes. Before deployment, narrow the
prefixes to public-only paths (or introduce a separate public-only allowlist)
and confirm that the backend enforces its own data-access authorization.

The existing application configuration, database migrations, and login flow
are not changed. `Program.cs` adds only a Swagger operation filter, to mark
anonymous endpoints as not requiring Bearer authorization in Swagger UI.

### Deploy

The source ZIP excludes `bin/`, `obj/` and previously published DLLs. Restore
your environment-specific `appsettings.json` or environment variables,
then run:

```bash
dotnet build
dotnet publish -c Release -o publish
```

If your Dockerfile contains `COPY publish/ .`, rebuild/recreate the image after
publishing the new DLL.

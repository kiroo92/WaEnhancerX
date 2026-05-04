# OTP Relay Server

Minimal standalone server for receiving OTP webhooks from WaEnhancerX.

Features:

- receive OTP webhooks
- store records in a local JSON file
- show recent OTPs in a web page
- expose HTTP APIs for external clients

## Start

Requirements:

- Node.js 18+

Run:

```bash
cd server
npm start
```

Default address:

- `http://0.0.0.0:8787`

Optional environment variables:

```bash
PORT=8787
HOST=0.0.0.0
OTP_STORE_LIMIT=500
OTP_DATA_FILE=./data/otp-store.json
CORS_ORIGIN=*
```

## WaEnhancerX webhook URL

Set the module `OTP Webhook URL` to:

```text
http://YOUR_SERVER_IP:8787/api/otp/webhook
```

Or use a public domain:

```text
https://your-domain.com/api/otp/webhook
```

## Webhook endpoint

`POST /api/otp/webhook`

Payload example:

```json
{
  "type": "otp",
  "source": "whatsapp",
  "code": "123456",
  "message": "Your verification code is 123456",
  "sender_name": "Telegram",
  "sender_number": "12345",
  "message_id": "ABCD1234",
  "chat_jid": "12345@s.whatsapp.net",
  "received_at": 1777900000000
}
```

It also accepts only message text and tries to extract the code:

```json
{
  "message": "Your login code is 654321",
  "sender_name": "Bank",
  "sender_number": "95588"
}
```

## Retrieval APIs

### Latest record

`GET /api/otp/latest`

Optional query params:

- `sender_number`
- `code`
- `source`

Example:

```text
GET /api/otp/latest?sender_number=12345
```

### Latest code as plain text

`GET /api/otp/latest.txt`

Example:

```text
GET /api/otp/latest.txt?sender_number=12345
```

Response:

```text
123456
```

### List records

`GET /api/otps`

Optional query params:

- `limit` default `20`, max `100`
- `sender_number`
- `code`
- `source`
- `after` ISO time or timestamp

Example:

```text
GET /api/otps?limit=50&sender_number=12345
```

### Health check

`GET /api/health`

## Web page

Dashboard:

```text
http://YOUR_SERVER_IP:8787/
```

The page auto-refreshes and shows:

- latest OTP
- recent messages
- ready-to-copy API examples

## Notes

- data is stored in `server/data/otp-store.json`
- the same `message_id` is updated instead of duplicated
- if `CORS_ORIGIN=*`, browser clients can call the API directly

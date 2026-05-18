# Recycle WiFi MongoDB Backend

This backend connects the Android app to MongoDB Atlas.

## Setup

1. Create a MongoDB Atlas cluster.
2. Create a database user.
3. Allow your IP address in Atlas Network Access.
4. Copy `.env.example` to `.env`.
5. Replace `MONGODB_URI` with your Atlas connection string.
6. Install and run:

```bash
npm install
npm start
```

The API runs on:

```text
http://localhost:3000
```

For Android emulator, the app uses:

```text
http://10.0.2.2:3000
```

For a real phone, edit `BackendClient.java` and replace `10.0.2.2` with your computer/server IP address.

## Collections

The API creates these MongoDB collections automatically:

- users
- transactions
- vouchers

## Test endpoint

Open this URL after starting the backend:

```text
http://localhost:3000/api/health
```

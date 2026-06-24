# Security Notes

## Defaults

- The teamserver now binds to `127.0.0.1:8080` by default.
- CORS is restricted to local development and Tauri origins unless overridden.
- `NAGOMIO_API_TOKEN` and `NAGOMIO_AGENT_TOKEN` should be set for real deployments.

## Environment variables

- `NAGOMIO_BIND_ADDR`
- `NAGOMIO_DB_PATH`
- `NAGOMIO_STATE_FILE`
- `NAGOMIO_PROJECT_ROOT`
- `NAGOMIO_PAYLOAD_DIR`
- `NAGOMIO_DOWNLOAD_DIR`
- `NAGOMIO_CALLBACK_URL`
- `NAGOMIO_DEFAULT_SLEEP_SECONDS`
- `NAGOMIO_API_TOKEN`
- `NAGOMIO_AGENT_TOKEN`
- `NAGOMIO_CORS_ORIGINS`
- `NAGOMIO_ALLOW_UNAUTHENTICATED`

## Notes

- Unauthenticated mode is allowed by default only for loopback binds.
- Payload artifact cleanup now removes on-disk build directories as well as database records.
- If you expose the API beyond localhost, set explicit auth tokens and review the allowed origins list.

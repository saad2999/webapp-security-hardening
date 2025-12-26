# Deploying the webapp to Google Cloud Run

This document describes a minimal path to containerize and deploy the app in this repository to Google Cloud Run, and how to connect it to a Cloud SQL (MySQL) instance.

Prerequisites
- A GCP project with billing enabled.
- Cloud SDK (`gcloud`) installed locally and authenticated.
- The following APIs enabled: Cloud Run, Cloud Build, Artifact Registry (or Container Registry), Cloud SQL Admin.

1) Build & test locally with Docker

Build the image locally:
```bash
docker build -t webapp:local .
```
Run with a local MySQL (or use `docker-compose up`):
```bash
docker-compose up --build
```
The app will be available at `http://localhost:8080`.

2) Create a Cloud SQL instance (MySQL)

Use Cloud Console or gcloud:
```bash
gcloud sql instances create clearway-sql \
  --database-version=MYSQL_8_0 --tier=db-f1-micro --region=us-central1

gcloud sql users set-password root % --instance=clearway-sql --password="your-db-password"

gcloud sql databases create Clearway_Cyber_db --instance=clearway-sql

gcloud sql import sql clearway-sql ./database.sql --database=Clearway_Cyber_db
```

3) Deploy to Cloud Run using Cloud Build (recommended)

This repo includes a `cloudbuild.yaml` that builds, pushes, and deploys. From the repo root:

```bash
gcloud builds submit --config cloudbuild.yaml --substitutions=COMMIT_SHA=$(git rev-parse --short HEAD),_REGION=us-central1,_CLOUDSQL_INSTANCE=YOUR_PROJECT:us-central1:clearway-sql
```

Notes:
- The Cloud Build step will deploy to Cloud Run and attach the Cloud SQL instance when `_CLOUDSQL_INSTANCE` substitution is provided.
- In Cloud Run you must set environment variables for `DB_HOST`/`DB_USER`/`DB_PASSWORD`/`DB_NAME`, and the security secrets `PEPPER` and `JWT_SECRET`. For Cloud SQL connections via the connector, use `DB_HOST` set to `/cloudsql/<INSTANCE_CONNECTION_NAME>` or use the built-in Cloud Run Cloud SQL connection configuration.

4) Setting env vars and secrets

Use Secret Manager for sensitive values and configure Cloud Run to mount or inject them. Example using `gcloud run deploy`:

```bash
gcloud run deploy webapp \
  --image gcr.io/$PROJECT_ID/webapp:$COMMIT_SHA \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars NODE_ENV=production,DB_USER=root,DB_NAME=Clearway_Cyber_db \
  --update-secrets "DB_PASSWORD=projects/$PROJECT_ID/secrets/DB_PASSWORD:latest,PEPPER=projects/$PROJECT_ID/secrets/PEPPER:latest,JWT_SECRET=projects/$PROJECT_ID/secrets/JWT_SECRET:latest" \
  --add-cloudsql-instances=YOUR_PROJECT:us-central1:clearway-sql
```

Replace `YOUR_PROJECT` and instance names appropriately.

5) Post-deploy checks
- Verify the service is running in Cloud Run.
- Check logs in Cloud Logging for `SUCCESSFUL_LOGIN` / `FAILED_LOGIN` messages.
- Confirm the app can connect to Cloud SQL and that `users` table exists.

Security recommendations
- Use Secret Manager for `PEPPER`, `JWT_SECRET`, and DB credentials.
- Use a private VPC connector or serverless VPC access if required for Cloud SQL private IP.
- Replace in-memory lockout and rate-limiter with Redis or Memorystore-backed stores for production.

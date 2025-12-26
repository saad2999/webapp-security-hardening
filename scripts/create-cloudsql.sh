#!/usr/bin/env bash
set -euo pipefail

# Creates Cloud SQL DB from database.sql, creates app user, and stores secrets.
# Usage: ./scripts/create-cloudsql.sh [PROJECT] [INSTANCE] [DB_NAME] [SQL_FILE] [WEBAPP_PW]

PROJECT=${1:-$(gcloud config get-value project)}
INSTANCE=${2:-clearway-sql}
DB_NAME=${3:-Clearway_Cyber_db}
SQL_FILE=${4:-database.sql}
WEBAPP_PW=${5:-change_this_secure_password}

if [ -z "$PROJECT" ]; then
  echo "Project not set. Pass as first arg or run 'gcloud config set project <PROJECT>'" >&2
  exit 2
fi

if [ ! -f "$SQL_FILE" ]; then
  echo "SQL file not found: $SQL_FILE" >&2
  exit 2
fi

BUCKET="${PROJECT}-db-imports"

echo "Using project: $PROJECT"
echo "Using instance: $INSTANCE"
echo "Database name: $DB_NAME"
echo "SQL file: $SQL_FILE"

echo "Ensuring GCS bucket gs://$BUCKET exists..."
if gsutil ls "gs://${BUCKET}" >/dev/null 2>&1; then
  echo "Bucket exists"
else
  echo "Creating bucket gs://$BUCKET"
  gsutil mb "gs://${BUCKET}"
fi

echo "Uploading $SQL_FILE to gs://$BUCKET/"
gsutil cp "$SQL_FILE" "gs://${BUCKET}/${SQL_FILE}"

echo "Starting import into Cloud SQL instance $INSTANCE..."
gcloud sql import sql "$INSTANCE" "gs://${BUCKET}/${SQL_FILE}" --database="$DB_NAME" --project="$PROJECT"

echo "Waiting for import operation to finish (polling up to 10 minutes)..."
SECS=0
while [ $SECS -lt 600 ]; do
  # Look for a recent IMPORT operation with status DONE
  OP_DONE=$(gcloud sql operations list --instance="$INSTANCE" --project="$PROJECT" --limit=10 --format="json" | \
    python3 -c "import sys, json
ops=json.load(sys.stdin)
for o in ops:
  if str(o.get('operationType','')).upper().find('IMPORT')!=-1 and o.get('status','')=='DONE':
    print('DONE')
    sys.exit(0)
print('')")
  if [ "$OP_DONE" = "DONE" ]; then
    echo "Import finished"
    break
  fi
  sleep 5
  SECS=$((SECS+5))
done
if [ $SECS -ge 600 ]; then
  echo "Warning: import may still be running (timeout reached). Check operations with: gcloud sql operations list --instance=$INSTANCE --project=$PROJECT" >&2
fi

echo "Creating/updating DB user 'webapp'..."
if gcloud sql users list --instance="$INSTANCE" --project="$PROJECT" --format="value(name)" | grep -q "^webapp$"; then
  echo "User exists, setting password"
  gcloud sql users set-password webapp --instance="$INSTANCE" --password="$WEBAPP_PW" --project="$PROJECT"
else
  echo "Creating user webapp"
  gcloud sql users create webapp --instance="$INSTANCE" --password="$WEBAPP_PW" --project="$PROJECT"
fi

echo "Pushing secrets to Secret Manager (DB_PASSWORD, PEPPER, JWT_SECRET) if present in .env"
ENV_FILE=.env
get_var(){
  key="$1"
  if [ -f "$ENV_FILE" ]; then
    grep -E "^${key}=" "$ENV_FILE" | cut -d'=' -f2- || true
  fi
}

create_or_update_secret(){
  name="$1"
  value="$2"
  if [ -z "$value" ]; then
    echo "Skipping empty secret: $name"
    return
  fi
  if gcloud secrets describe "$name" --project="$PROJECT" >/dev/null 2>&1; then
    echo "Adding new version to secret $name"
    printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- --project="$PROJECT" >/dev/null
  else
    echo "Creating secret $name"
    printf '%s' "$value" | gcloud secrets create "$name" --replication-policy="automatic" --data-file=- --project="$PROJECT" >/dev/null
  fi
}

# prefer DB_PASSWORD from .env, otherwise use WEBAPP_PW
DB_PASSWORD=$(get_var DB_PASSWORD)
if [ -z "$DB_PASSWORD" ]; then
  DB_PASSWORD="$WEBAPP_PW"
fi
JWT_SECRET=$(get_var JWT_SECRET)
PEPPER=$(get_var PEPPER)

create_or_update_secret DB_PASSWORD "$DB_PASSWORD"
create_or_update_secret PEPPER "$PEPPER"
create_or_update_secret JWT_SECRET "$JWT_SECRET"

echo "Done. Verify with: gcloud sql users list --instance=$INSTANCE --project=$PROJECT"

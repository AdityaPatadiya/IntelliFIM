echo "=== Step 1: Dropping and recreating databases ==="
sudo -u postgres psql << EOF
DROP DATABASE IF EXISTS auth_dev;
DROP DATABASE IF EXISTS fim_dev;
CREATE DATABASE auth_dev WITH OWNER fim_dev_user ENCODING 'UTF8';
CREATE DATABASE fim_dev WITH OWNER fim_dev_user ENCODING 'UTF8';

\c auth_dev
GRANT ALL ON SCHEMA public TO fim_dev_user;
GRANT CREATE ON SCHEMA public TO fim_dev_user;

\c fim_dev
GRANT ALL ON SCHEMA public TO fim_dev_user;
GRANT CREATE ON SCHEMA public TO fim_dev_user;
EOF

echo "=== Step 2: Deleting migration files ==="
# Delete all migration files except __init__.py
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc" -delete

echo "=== Step 3: Creating new migrations ==="
python manage.py makemigrations accounts
python manage.py makemigrations fim

echo "=== Step 4: Migrating auth_db FIRST ==="
# First, migrate Django's built-in auth apps to auth_db
python manage.py migrate auth --database=auth_db
python manage.py migrate contenttypes --database=auth_db

# Then migrate accounts (depends on auth and contenttypes)
python manage.py migrate accounts --database=auth_db

# Then migrate admin (depends on contenttypes and accounts)
python manage.py migrate admin --database=auth_db

echo "=== Step 5: Migrating default database ==="
# Migrate everything else to default database
python manage.py migrate --database=default

echo "=== Step 6: Verify databases ==="
echo "Tables in auth_dev:"
sudo -u postgres psql -d auth_dev -c "\dt"
echo ""
echo "Tables in fim_dev:"
sudo -u postgres psql -d fim_dev -c "\dt"

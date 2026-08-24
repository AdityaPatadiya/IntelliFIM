-- Postgres init for IntelliFIM.
-- Runs once on first container init (when the data volume is empty).
--
-- POSTGRES_DB env creates the main DB (fim_db). This script adds auth_db
-- with the same owner so the Django auth router can target it.

CREATE DATABASE auth_db OWNER fim_user;
GRANT ALL PRIVILEGES ON DATABASE auth_db TO fim_user;
ALTER USER fim_user CREATEDB;  -- allow pytest to spin up test DBs

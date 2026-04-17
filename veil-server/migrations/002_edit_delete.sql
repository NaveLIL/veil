-- Veil Server Schema — edit & delete support
-- Version 2

ALTER TABLE messages ADD COLUMN edited_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE signup_tokens ADD COLUMN target BLOB CHECK (target IS NULL OR length(target) = 16);

-- Migration: Allow NULL for mobile and email in otp_tokens
ALTER TABLE otp_tokens ALTER COLUMN mobile DROP NOT NULL;
ALTER TABLE otp_tokens ALTER COLUMN email DROP NOT NULL;

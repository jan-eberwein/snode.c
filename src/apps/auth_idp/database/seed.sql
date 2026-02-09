-- SNode.C SSO/MFA Seed Data
-- Test users for development and demonstration
-- Password hashing: SHA-256 with salt
-- Format: SHA256(password + salt)
--
-- TOTP Secrets are Base32 encoded, compatible with Google/Microsoft Authenticator
--
-- IMPORTANT: Hashes computed with: echo -n "password+salt" | shasum -a 256

-- Test user with TOTP enabled
-- Username: testuser
-- Password: password
-- Salt: testsalt123
-- Hash: SHA256("passwordtestsalt123") = 2db836f99495ba8ec3e19a99f246b954dde589fb79ff64b9112ba46081923394
-- TOTP Secret: JBSWY3DPEHPK3PXP (manually enter or scan QR code)
INSERT INTO `user` (`username`, `email`, `password_hash`, `password_salt`, `totp_secret`, `totp_enabled`) VALUES
('testuser', 'test@example.com', '2db836f99495ba8ec3e19a99f246b954dde589fb79ff64b9112ba46081923394', 'testsalt123', 'JBSWY3DPEHPK3PXP', TRUE);

-- Normal user without TOTP
-- Username: normaluser
-- Password: password
-- Salt: normalsalt456
-- Hash: SHA256("passwordnormalsalt456") = 77a3d9195937bdd5d16a80059ecee2e914055c055fdb58cf81e3e6cb2c4be0dc
INSERT INTO `user` (`username`, `email`, `password_hash`, `password_salt`, `totp_secret`, `totp_enabled`) VALUES
('normaluser', 'normal@example.com', '77a3d9195937bdd5d16a80059ecee2e914055c055fdb58cf81e3e6cb2c4be0dc', 'normalsalt456', NULL, FALSE);

-- Admin user with TOTP
-- Username: admin
-- Password: admin123
-- Salt: adminsalt789
-- Hash: SHA256("admin123adminsalt789") = 7307f78c9244e00526debeabb074fc6b9987b2594c2da6a2ed9269aac3511b51
-- TOTP Secret: KRUGC43FMZRW63LM
INSERT INTO `user` (`username`, `email`, `password_hash`, `password_salt`, `totp_secret`, `totp_enabled`) VALUES
('admin', 'admin@example.com', '7307f78c9244e00526debeabb074fc6b9987b2594c2da6a2ed9269aac3511b51', 'adminsalt789', 'KRUGC43FMZRW63LM', TRUE);

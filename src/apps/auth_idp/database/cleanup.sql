-- Cleanup script
-- WARNING: This will delete all data!

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `access_token`;
DROP TABLE IF EXISTS `auth_code`;
DROP TABLE IF EXISTS `session`;
DROP TABLE IF EXISTS `user`;

SET FOREIGN_KEY_CHECKS = 1;

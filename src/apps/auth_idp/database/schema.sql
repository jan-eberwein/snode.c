-- SNode.C SSO/MFA Database Schema
-- User authentication and OAuth2 authorization codes

-- User table with authentication and TOTP
CREATE TABLE IF NOT EXISTS `user` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) NOT NULL UNIQUE,
    `email` VARCHAR(255) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `password_salt` VARCHAR(255) NOT NULL,
    `totp_secret` VARCHAR(32) DEFAULT NULL,
    `totp_enabled` BOOLEAN DEFAULT FALSE,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX `idx_username` (`username`),
    INDEX `idx_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- OAuth2 Authorization Codes
CREATE TABLE IF NOT EXISTS `auth_code` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `code` VARCHAR(255) NOT NULL UNIQUE,
    `user_id` INT NOT NULL,
    `client_id` VARCHAR(255) NOT NULL,
    `redirect_uri` TEXT NOT NULL,
    `scope` VARCHAR(255) DEFAULT NULL,
    `state` VARCHAR(255) DEFAULT NULL,
    `code_challenge` VARCHAR(255) DEFAULT NULL,
    `code_challenge_method` VARCHAR(10) DEFAULT NULL,
    `expires_at` TIMESTAMP NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE,
    INDEX `idx_code` (`code`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- OAuth2 Access Tokens (Optional - for token persistence)
CREATE TABLE IF NOT EXISTS `access_token` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `token` VARCHAR(255) NOT NULL UNIQUE,
    `user_id` INT NOT NULL,
    `client_id` VARCHAR(255) NOT NULL,
    `scope` VARCHAR(255) DEFAULT NULL,
    `expires_at` TIMESTAMP NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE,
    INDEX `idx_token` (`token`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sessions for multi-step authentication flow
CREATE TABLE IF NOT EXISTS `session` (
    `id` VARCHAR(255) PRIMARY KEY,
    `user_id` INT DEFAULT NULL,
    `data` TEXT,
    `expires_at` TIMESTAMP NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE,
    INDEX `idx_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

/*
 * SNode.C - A Slim Toolkit for Network Communication
 * Copyright (C) Volker Christian <me@vchrist.at>
 *               2020, 2021, 2022, 2023, 2024, 2025
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "database/sqlite/SqliteDatabase.h"

#include <sqlite3.h>
#include <stdexcept>
#include <string>

namespace snodec::database::sqlite {

    // ========================================================================
    // Row
    // ========================================================================

    SqliteDatabase::Row::Row(sqlite3_stmt* stmt)
        : stmt_(stmt) {
    }


    int SqliteDatabase::Row::columnCount() const {
        return sqlite3_column_count(stmt_);
    }

    std::string SqliteDatabase::Row::get(int index) const {
        // sqlite3_column_text returns NULL for SQL NULL or if index is OOB.
        const unsigned char* raw = sqlite3_column_text(stmt_, index);
        return raw ? reinterpret_cast<const char*>(raw) : "";
    }

    std::string SqliteDatabase::Row::get(const std::string& name) const {
        const int count = sqlite3_column_count(stmt_);
        for (int i = 0; i < count; ++i) {
            const char* colName = sqlite3_column_name(stmt_, i);
            if (colName && name == colName) {
                return get(i);
            }
        }
        return "";
    }

    bool SqliteDatabase::Row::isNull(int index) const {
        return sqlite3_column_type(stmt_, index) == SQLITE_NULL;
    }

    // ========================================================================
    // SqliteDatabase — Construction / Destruction
    // ========================================================================

    SqliteDatabase::SqliteDatabase(const std::string& filePath)
        : db_(nullptr) {
        // SQLITE_OPEN_CREATE  – create if it doesn't exist.
        // SQLITE_OPEN_READWRITE – allow reads and writes.
        // SQLITE_OPEN_FULLMUTEX – serialised threading mode (safe default).
        const int rc = sqlite3_open_v2(filePath.c_str(),
                                       &db_,
                                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                       nullptr);
        if (rc != SQLITE_OK) {
            const std::string msg = db_ ? sqlite3_errmsg(db_) : "unknown error";
            sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("SqliteDatabase: cannot open '" + filePath + "': " + msg);
        }

        // Enable WAL for better concurrent-read performance.
        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        // Enforce foreign-key constraints.
        sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
        // Reasonable busy timeout: 5 s.
        sqlite3_busy_timeout(db_, 5000);
    }

    SqliteDatabase::~SqliteDatabase() {
        if (db_ != nullptr) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    // ========================================================================
    // Schema Initialisation
    // ========================================================================

    void SqliteDatabase::initSchema() {
        static const char* SCHEMA = R"(
            -- Users table
            CREATE TABLE IF NOT EXISTS user (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                username         TEXT    NOT NULL UNIQUE,
                email            TEXT    NOT NULL UNIQUE,
                password_hash    TEXT    NOT NULL,
                password_salt    TEXT    NOT NULL,
                totp_secret      TEXT    DEFAULT NULL,
                totp_enabled     INTEGER DEFAULT 0,
                created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- OAuth2 authorisation codes (short-lived, single-use)
            CREATE TABLE IF NOT EXISTS auth_code (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                code                 TEXT    NOT NULL UNIQUE,
                user_id              INTEGER NOT NULL,
                client_id            TEXT    NOT NULL,
                redirect_uri         TEXT    NOT NULL,
                scope                TEXT    NOT NULL,
                state                TEXT    NOT NULL,
                code_challenge       TEXT    DEFAULT NULL,
                code_challenge_method TEXT   DEFAULT NULL,
                created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at           DATETIME NOT NULL,
                mfa_verified         INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
            );

            -- Password reset tokens
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token       TEXT    NOT NULL UNIQUE,
                user_id     INTEGER NOT NULL,
                expires_at  DATETIME NOT NULL,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
            );

            -- Active login sessions
            CREATE TABLE IF NOT EXISTS session (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token       TEXT    NOT NULL UNIQUE,
                user_id     INTEGER NOT NULL,
                expires_at  DATETIME NOT NULL,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
            );



            -- Index for fast auth_code lookup
            CREATE INDEX IF NOT EXISTS idx_auth_code_code
                ON auth_code (code);

            -- Index for fast reset-token lookup
            CREATE INDEX IF NOT EXISTS idx_reset_token
                ON password_reset_tokens (token);
        )";

        char* errmsg = nullptr;
        const int rc = sqlite3_exec(db_, SCHEMA, nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string msg = errmsg ? errmsg : "unknown error";
            sqlite3_free(errmsg);
            throw std::runtime_error("SqliteDatabase::initSchema failed: " + msg);
        }
    }

    // ========================================================================
    // Internal helper: prepare + bind
    // ========================================================================

    sqlite3_stmt* SqliteDatabase::prepare(const std::string& sql,
                                          const std::vector<std::string>& params,
                                          std::string* errmsg) {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            if (errmsg) {
                *errmsg = sqlite3_errmsg(db_);
            }
            return nullptr;
        }

        // Bind parameters positionally (1-based in SQLite API).
        for (int i = 0; i < static_cast<int>(params.size()); ++i) {
            rc = sqlite3_bind_text(stmt,
                                   i + 1,
                                   params[static_cast<size_t>(i)].c_str(),
                                   -1,
                                   SQLITE_TRANSIENT);
            if (rc != SQLITE_OK) {
                if (errmsg) {
                    *errmsg = sqlite3_errmsg(db_);
                }
                sqlite3_finalize(stmt);
                return nullptr;
            }
        }

        return stmt;
    }

    // ========================================================================
    // exec – run a DML/DDL statement (no result rows expected)
    // ========================================================================

    bool SqliteDatabase::exec(const std::string& sql,
                               const std::vector<std::string>& params,
                               std::string* errmsg) {
        sqlite3_stmt* stmt = prepare(sql, params, errmsg);
        if (stmt == nullptr) {
            return false;
        }

        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            if (errmsg) {
                *errmsg = sqlite3_errmsg(db_);
            }
            return false;
        }
        return true;
    }

    // ========================================================================
    // query – run a SELECT and invoke callback for every row
    // ========================================================================

    bool SqliteDatabase::query(const std::string& sql,
                                const std::vector<std::string>& params,
                                const RowCallback& callback,
                                std::string* errmsg) {
        sqlite3_stmt* stmt = prepare(sql, params, errmsg);
        if (stmt == nullptr) {
            return false;
        }

        int rc = SQLITE_ROW;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            Row row(stmt);
            callback(row);
        }

        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            if (errmsg) {
                *errmsg = sqlite3_errmsg(db_);
            }
            return false;
        }
        return true;
    }

    bool SqliteDatabase::query(const std::string& sql,
                                const RowCallback& callback,
                                std::string* errmsg) {
        return query(sql, {}, callback, errmsg);
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    int64_t SqliteDatabase::lastInsertRowid() const {
        return sqlite3_last_insert_rowid(db_);
    }

    int SqliteDatabase::changedRows() const {
        return sqlite3_changes(db_);
    }

} // namespace snodec::database::sqlite

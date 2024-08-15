THE FOLLOWING CODE IS MENT OT BE COPPIED
THE FILE NAMES ARE WHERE YOU COPY THE CODE TO

CREATE TABLE users (
  id TEXT PRIMARY KEY, -- UUID from github.com/google/uuid newUUID := uuid.New().String()
  username TEXT      NOT NULL,
  email  TEXT        NOT NULL,
  password TEXT      NOT NULL,
);

CREATE TABLE tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

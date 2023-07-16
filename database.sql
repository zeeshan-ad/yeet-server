CREATE DATABASE yeet;
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP dob DATE NOT NULL,
);

-- OTP reset password
CREATE TABLE user_otp (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    otp VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE user_profile (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    bio VARCHAR(255) NOT NULL,
    profile_pic VARCHAR(255) NOT NULL,
    theme VARCHAR(255) NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE user_mood (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    mood TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE user_posts_memos (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    memo TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE friends_requests (
    id SERIAL PRIMARY KEY,
    req_by_id INT NOT NULL,
    req_to_id INT NOT NULL,
    status VARCHAR(255) NOT NULL,
    notify BOOL NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE user_posts_moments (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    moment VARCHAR NOT NULL,
    caption TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DB to hold Likes
CREATE TABLE user_posts_likes (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    post_id INT NOT NULL,
    post_type VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DB to hold Comments
CREATE TABLE user_posts_comments (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    post_id INT NOT NULL,
    post_type VARCHAR(255) NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
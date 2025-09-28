# Personal Link Shortener API

This is a complete backend API for a personal URL shortening service, built with FastAPI and MongoDB. It features a full authentication system, CRUD operations for links, and an analytics endpoint.

## Features

* User registration and login with secure password hashing (bcrypt).
* JWT-based authentication for all protected endpoints.
* Full CRUD (Create, Read, Delete) functionality for links.
* Authorization layer to ensure users can only manage their own links.
* Automatic click tracking for each redirect.
* An analytics endpoint (`/stats/my-links`) using a MongoDB Aggregation Pipeline.

## Tech Stack

* **Framework:** FastAPI
* **Database:** MongoDB (with MongoDB Atlas)
* **Security:** Passlib (for hashing), python-jose (for JWT)
* **Version Control:** Git & GitHub

## API Endpoints

A full list of endpoints can be tested using the Postman collection or by running the app and navigating to `/docs`.
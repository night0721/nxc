# nxc
<p align="center">
    <a href="https://ko-fi.com/I2I35XISJ" target="_blank"><img alt='Kofi' src="https://img.shields.io/static/v1?label=Support%20Us&message=KO.FI&color=ff5e5b&logo=kofi&logoColor=white&style=for-the-badge&scale=1.4">
    </a> <br>
</p>

NightX Client File Uploader is a simple host for file uploader, paste bin and URL shortener, with oauth and dashboard.

# Usage
```sh
./start
```

You would need to fill .env.example then rename it to .env for the backend server to work, and `nginx.conf` is provided for reverse proxy.

## Routes

### Authentication

* **GET** `/auth/github/login` — Initiates GitHub OAuth2 flow.
* **GET** `/auth/github/callback` — Handles the redirection from GitHub and exchanges the code for a token.
* **GET** `/auth/me` — Returns the currently authenticated user's profile.
* **POST** `/auth/logout` — Invalidates the session and clears the cookie.

### URL Shortener

* **POST** `/` — Creates a new short link (by providing the `url` field).
* **GET** `/s/:slug` — Redirects the browser to the original long URL.

### Pastebin

* **POST** `/` — Submits a new paste (by providing the `content` field).
* **GET** `/i/:slug` — Displays the highlighted paste in the web viewer.
* **GET** `/i/raw/:slug` — Returns the raw text content of the paste.

### Files & Images

* **POST** `/` — Uploads a single file/image via Multipart (by providing the `file` field).
* **GET** `/i/:slug` — Displays the file/image/code in the web viewer.
* **GET** `/i/raw/:slug` — Serves the raw file with the original mime-type.
* **GET** `/i/bin/:slug` — Direct file/image download as attachment.

### Management

* **GET** `/api/urls` — Lists all short URLs owned by the current user.
* **GET** `/api/files` — Lists all uploaded files and pastes owned by the current user.
* **POST** `/api/:kind/delete` — Deletes a record by type (where `:kind` is `url` or `file`).
* **POST** `/api/webhooks` — Registers a Discord webhook for upload notifications.

# Building
You will need to run these with elevated privilages.
```sh
# For backend
cd backend
cargo install nxs

# For cli
cd cli
cargo install nxc

# For frontend
cd frontend
npm i
npm run build
```

# Contributions
Contributions are welcomed, feel free to open a pull request.

# License
This project is licensed under the GNU Public License v3.0. See [LICENSE](https://github.com/night0721/nxc/blob/master/LICENSE) for more information.

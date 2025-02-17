# Pass Man

A secure, self-hosted **password manager** with **autofill capabilities** for Chromium-based browsers. This project is designed to securely store credentials and automatically fill login fields.

## 🚀 Features
- Securely store passwords using **zero-knowledge encryption**
- Autofill credentials based on the **current website**
- **Master password hashing** for secure authentication
- **Dockerized** for easy deployment
- Self-hosted with **Flask backend**

## 🛠️ Installation (Using Docker)
### 1️⃣ **Pull the Docker Image**
```sh
docker pull vickm81/pass-man
```

### 2️⃣ **Run the Container**
```sh
docker run -d -p 5000:5000 --name pass-man vickm81/pass-man
```
This will start the password manager on `http://localhost:5000`.

### 3️⃣ **Load the Browser Extension**
The browser extension can be found at https://github.com/vickm81/pass-man-ext
1. Open **Chrome** and go to `chrome://extensions/`
2. Enable **Developer Mode** (toggle in the top-right corner)
3. Click **Load unpacked** and select the `extension/` folder
4. The extension should now be installed and ready to use

## 🔐 Usage
1. **Register/Login** with your master password
2. **Save passwords** securely in the vault
3. **Autofill credentials** when visiting a saved website

## 📦 Building the Docker Image (For Development)
If you want to modify the project, build your own Docker image:
```sh
docker build -t pass-man .
```
Then run:
```sh
docker run -d -p 5000:5000 --name pass-man pass-man
```

## 📝 API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/register` | Register a new user |
| `POST` | `/login` | Authenticate user |
| `GET` | `/get_credentials?website=example.com` | Retrieve stored credentials |

## 🤝 Contributing
Feel free to fork and submit pull requests!

## ⚖️ License
MIT License

---
💡 **Tip:** If you encounter issues, check the logs using:
```sh
docker logs pass-man
```


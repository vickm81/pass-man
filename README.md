# Pass Man

A secure, self-hosted **password manager** with **autofill capabilities** for Chromium-based browsers. This project is designed to securely store credentials and automatically fill login fields.

## 🚀 Features
- Securely store passwords using **zero-knowledge encryption**
- Autofill credentials based on the **current website**
- **Master password hashing** for secure authentication
- **Dockerized** for easy deployment
- Self-hosted with **Flask backend**

## 🛠️ Installation

### 📦 Quick Setup (Ubuntu / Fedora / Windows)

To get started, **you only need the setup script** for your platform. The script will handle:
- Installing Docker (if not already installed)
- Pulling the Pass Man Docker image
- Starting the container on `http://localhost:5000`

---

### 💻 Linux (Ubuntu / Fedora)

1. **Download the setup script**  
   ```sh
   curl -O https://raw.githubusercontent.com/user/repo/main/setup.sh

2. Open a terminal and run:
   ```sh
   chmod +x setup.sh
   sudo ./setup.sh

### 🪟 Windows
1. [Download Docker Desktop Installer](https://www.docker.com/products/docker-desktop/)

2. **Download the setup script**

3. **Right-click setup.bat → Run as Administrator**

### 2️⃣ **Load the Browser Extension**
The browser extension can be found at https://github.com/vickm81/pass-man-ext
1. Open **Chrome** and go to `chrome://extensions/`
2. Enable **Developer Mode** (toggle in the top-right corner)
3. Click **Load unpacked** and select the `extension/` folder
4. The extension should now be installed and ready to use

## 🔐 Usage
1. **Register/Login** with your master password
2. **Save passwords** securely in the vault
3. **Autofill credentials** when visiting a saved website by clicking on the extension

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


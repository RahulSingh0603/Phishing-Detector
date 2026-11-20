# PhishGuard AI

A real-time, privacy-preserving AI phishing and malicious URL detector. 
PhishGuard AI analyzes URLs locally using a machine learning model to protect users from navigating to dangerous websites.

## 🚀 Features

- **Local Machine Learning**: Uses an XGBoost model to classify URLs (Safe, Suspicious, Phishing, Malicious) without sending your browsing history to the cloud.
- **Chrome Extension**: Intercepts navigation attempts, analyzes the URL, and blocks access to dangerous sites with a warning page.
- **Background API Service**: A FastAPI backend that serves predictions and logs history to a local SQLite database.
- **Heuristic Risk Engine**: Combines ML probabilities with rule-based heuristics (e.g., unusual TLDs, IP addresses, suspicious keywords).
- **Web Dashboard**: View your scanning history, detection distribution, and statistics.
- **Privacy First**: URLs are processed locally by default.

## 🏗️ Architecture

1. **Frontend**: Chrome/Chromium Browser Extension (Manifest V3) + Dashboard (HTML/JS/CSS).
2. **Backend API**: Python FastAPI + Uvicorn + SQLite.
3. **ML Pipeline**: Scikit-Learn + XGBoost for URL feature extraction and prediction.

## 🛠️ Technology Stack

- **Python 3.11+**: Core backend logic.
- **FastAPI**: REST API framework.
- **XGBoost & Scikit-learn**: Machine learning and data processing.
- **JavaScript & Manifest V3**: Chrome extension architecture.
- **Chart.js**: Dashboard analytics visualization.
- **SQLite**: Local data persistence.

## 📦 Installation & Setup

### 1. Backend Setup

Open a terminal in the project directory and run:

```bash
# Create a virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate
# For Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Dataset Setup & Model Training

PhishGuard AI uses real-world, verified threat intelligence feeds (**PhishTank**, **OpenPhish** zero-day active feeds, and **Tranco/Global Top-ranked** legitimate domains):

```bash
# Fetch live real-time feeds and compile a balanced 10,000 URL dataset
python dataset/generate_dataset.py

# Train the tuned XGBoost classifier on the real dataset
python backend/ml/train.py
```

### 3. Start the Backend API

You can start the backend manually for debugging:

```bash
uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
```
*Or use the provided background script (Windows):*
Double-click `scripts/start_windows.bat` to run the service in the background. (Use `scripts/stop_windows.bat` to terminate it).

### 4. Chrome Extension Setup

1. Open Chrome/Edge/Brave and navigate to `chrome://extensions/`.
2. Enable **Developer Mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the `extension/` folder inside this project.
5. The PhishGuard AI icon should now appear in your browser toolbar.

### 5. Dashboard Setup

Simply double-click `dashboard/index.html` to open the local dashboard in your browser. It will automatically connect to the local API on port 8000.

## 📖 API Documentation

Once the backend is running, visit:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Redoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

## 🧪 Testing

Test the backend system using `pytest`:

```bash
pytest tests/
```

### Manual Testing with the Extension:
- **Safe**: Navigate to `https://google.com` (Should load normally).
- **Phishing**: Try navigating to `http://update-account-security.info/login.php` (Should trigger the red warning page).

## 🔒 Security & Privacy

- **Local Processing**: By default, no URLs leave your machine.
- **Optional External APIs**: You can enable VirusTotal by adding an API key in the `.env` file.
- **No Scraping**: Only the URL string is analyzed. Page content, cookies, and passwords are never collected.

## 🔮 Future Improvements (Placement-Ready)

- Expand the dataset to include hundreds of thousands of real-world benign and malicious URLs (e.g., from PhishTank).
- Implement deep learning (e.g., 1D CNNs or LSTMs) on character-level URL representations.
- Connect the dashboard to a live WebSocket for real-time notifications.
- Optimize the extension to cache safe URLs aggressively, minimizing backend calls.

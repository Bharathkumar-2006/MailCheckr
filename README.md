# MailCheckr - Email Inspector & Security Dashboard

MailCheckr is an advanced browser extension designed to audit email safety. It provides a premium-styled dashboard containing email sender checks, message header analyses, and link scans to protect users against phishing attempts, spam, and identity spoofing.

---

## Key Features

### 1. Sender Reputation Checker
- Checks active sender emails against spam databases to retrieve deliverability status and fraud risk.
- Returns a graphical report detailing deliverability, spam score (0-100), and first seen timestamps.

### 2. Email Header Analyzer
- Allows pasting of raw email headers (extracted from Gmail, Outlook, etc.).
- Parses and displays:
  - **Metadata**: From, Return-Path, and originating Sender IP address.
  - **Email Signatures**: Extraction of **SPF**, **DKIM**, and **DMARC** results.
  - **Authentication Badging**: Color-coded badges indicating verification status (Green = Pass, Yellow = Warning/Neutral, Red = Fail).
  - **Routing Timeline Flow**: Reconstructs a chronological step-by-step received chain detailing each server hop, IP address, and transit timestamps.

### 3. Malicious Link Scanner
- Parses plain-text or HTML message bodies to extract all URLs.
- Audits domains against five strict phishing heuristics:
  - **IP Hostnames**: Flagging raw IPv4/IPv6 addresses.
  - **Punycode**: Detecting Internationalized Domain Name (IDN) homograph attacks.
  - **URL Shorteners**: Identifying hiding destinations (e.g. `bit.ly`, `tinyurl.com`).
  - **Suspicious TLDs**: Detecting high-abuse top-level domains (e.g. `.zip`, `.mov`, `.win`, `.loan`).
  - **Lookalike Brands**: Detecting combo-squatting, typosquatting (homoglyphs like `paypa1.com` -> `paypal`), and subdomain spoofing (`paypal.com.scam.net`).
- Displays scan results in an interactive table detailing the target URL, calculated risk level (Low, Medium, High), and explanations for each issue.

---

## Directory Structure

```text
MailCheckr/
├── extension/                 # Chrome Extension files
│   ├── login.html             # User login page
│   ├── register.html          # User registration page
│   ├── popup.html             # Main dashboard UI
│   ├── manifest.json          # Chrome MV3 manifest configuration
│   ├── styles/
│   │   └── popup.css          # Premium dark-theme styling sheet
│   └── scripts/
│       ├── auth.js            # User authenticator handlers
│       ├── background.js      # Background service worker script
│       ├── content.js         # Gmail DOM sender-email extractor
│       ├── popup.js           # Form binders and UI rendering logic
│       └── utils.js           # Header parsing & Link scanning engine
└── backend/                   # Express & MongoDB backend service
    ├── server.js              # Server bootstrapper
    ├── config/                # Database configurations
    ├── controllers/           # Route handler controllers
    ├── middleware/            # JWT authentication middleware
    ├── models/                # MongoDB models (User)
    ├── routes/                # Endpoint routers
    ├── package.json           # Backend npm dependencies and scripts
    └── tests/
        └── utils.test.js      # Jest unit test suite for utils.js
```

---

## Installation & Setup

### 1. Prerequisites
- [Node.js](https://nodejs.org/) (v16+)
- [MongoDB](https://www.mongodb.com/try/download/community) running locally or remotely.

### 2. Backend Setup
1. Open a terminal and navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install the dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file in the `backend/` directory with the following variables:
   ```env
   PORT=5000
   MONGO_URI=mongodb://localhost:27017/mailcheckr
   JWT_SECRET=your_jwt_secret_key
   IPQS_API_KEY=your_ipqualityscore_api_key
   ```
4. Start the server:
   ```bash
   npm start
   ```
   The backend server will run on `http://localhost:5000`.

### 3. Load the Browser Extension
1. Open Google Chrome and go to `chrome://extensions/`.
2. Turn on **Developer mode** using the toggle switch in the upper-right corner.
3. Click the **Load unpacked** button in the upper-left corner.
4. Select the `extension/` directory of the project.
5. The MailCheckr extension icon will now appear in your browser toolbar.

---

## Running Unit Tests
We have built unit tests to validate the header parser and link scanning heuristics.

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Run the test command:
   ```bash
   npm test
   ```
   This will execute the Jest test suite located in `backend/tests/utils.test.js` against the extension's `scripts/utils.js` code.

# FortKnoxx -   

A comprehensive security scanning platform that analyzes GitHub/GitLab repositories for vulnerabilities, code quality issues, and license compliance using **16 free and open-source** scanning tools.

## Features

- **Security Scanning (8 tools)**: Semgrep, Gitleaks, Trivy, Checkov, Bandit, TruffleHog, Grype, ESLint Security
- **Code Quality Analysis (5 tools)**: Pylint, Flake8, Radon, ShellCheck, Hadolint
- **License Compliance (3 tools)**: pip-audit, npm-audit, Syft (SBOM)
- **AI-Powered Fix Recommendations**: Generate fixes using OpenAI, Anthropic Claude, or Google Gemini
- **Multi-Score Dashboard**: Security Score, Quality Score, Compliance Score
- **OWASP Top 10 Mapping**: Categorize findings by OWASP standards
- **SBOM Generation**: Software Bill of Materials in multiple formats
- **Comprehensive Reporting**: Export reports in JSON/CSV formats

## Integrated Scanners (All FREE & Open Source)

| Category | Tool | Purpose | License |
|----------|------|---------|---------|
| **SAST** | Semgrep | Multi-language static analysis | LGPL |
| **SAST** | Bandit | Python security linter | Apache-2.0 |
| **SAST** | ESLint Security | JavaScript/TypeScript security | MIT |
| **Secrets** | Gitleaks | Git history secret detection | MIT |
| **Secrets** | TruffleHog | Active secret verification | AGPL-3.0 |
| **Dependencies** | Trivy | Filesystem/container vulnerabilities | Apache-2.0 |
| **Dependencies** | Grype | Multi-language dependency scanning | Apache-2.0 |
| **Dependencies** | pip-audit | Python package vulnerabilities | Apache-2.0 |
| **Dependencies** | npm-audit | Node.js package vulnerabilities | Built-in |
| **IaC** | Checkov | Terraform/K8s/CloudFormation | Apache-2.0 |
| **Quality** | Pylint | Python code quality | GPL-2.0 |
| **Quality** | Flake8 | PEP 8 style enforcement | MIT |
| **Quality** | Radon | Code complexity metrics | MIT |
| **Quality** | ShellCheck | Shell script analysis | GPL-3.0 |
| **Quality** | Hadolint | Dockerfile best practices | GPL-3.0 |
| **Compliance** | Syft | SBOM generation | Apache-2.0 |

## Requirements

### Backend
- **Python 3.10** (required)
- MongoDB (local or remote)
- Security scanning tools (optional but recommended):
  - Semgrep
  - Gitleaks
  - Trivy
  - Checkov

### Frontend
- Node.js 16+ and Yarn
- Modern web browser

## Installation

### 1. Install Python 3.10

**macOS (Homebrew):**
```bash
brew install python@3.10
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3.10 python3.10-venv python3.10-dev
```

**Windows:**
Download from [python.org](https://www.python.org/downloads/)

### 2. Install MongoDB

**macOS:**
```bash
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb-community
```

**Ubuntu/Debian:**
```bash
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo systemctl start mongod
```

### 3. Install All Scanning Tools (Recommended)

Run the automated installation script to install all 16 scanners:

```bash
chmod +x install_scanners.sh
./install_scanners.sh
```

This will install:
- **Security**: Semgrep, Gitleaks, Trivy, Checkov, Bandit, TruffleHog, Grype, ESLint
- **Quality**: Pylint, Flake8, Radon, ShellCheck, Hadolint
- **Compliance**: pip-audit, npm-audit (built-in), Syft

**Or install manually:**

```bash
# Python tools
pip3.10 install semgrep bandit checkov pylint flake8 radon pip-audit safety

# macOS (Homebrew)
brew install gitleaks trivy trufflehog grype shellcheck hadolint syft

# npm tools
npm install -g eslint eslint-plugin-security
```

## Quick Start

### Automated Setup

Run the startup script to automatically set up and start both backend and frontend:

```bash
chmod +x start_servers.sh
./start_servers.sh
```

This will:
- Start MongoDB (if not running)
- Create Python 3.10 virtual environment
- Install backend dependencies
- Start backend server on port 8000
- Install frontend dependencies
- Start frontend on port 3000

### Manual Setup

**Backend:**
```bash
cd backend
python3.10 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn server:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
yarn install
yarn start
```

## Configuration

### Backend Environment Variables

Create `backend/.env`:
```env
MONGO_URL=mongodb://localhost:27017
DB_NAME=fortknox_db
CORS_ORIGINS=*
LLM_KEY=your_api_key_here
```

### Frontend Environment Variables

Create `frontend/.env`:
```env
REACT_APP_BACKEND_URL=http://localhost:8000
WDS_SOCKET_PORT=443
REACT_APP_ENABLE_VISUAL_EDITS=false
ENABLE_HEALTH_CHECK=false
```

## Usage

1. **Add Repository**: Navigate to "Add Repository" and provide:
   - Repository name
   - Git URL
   - Access token
   - Branch name

2. **Start Scan**: Click "Start Scan" to begin security analysis

3. **Review Results**: View vulnerabilities organized by severity and OWASP category

4. **Get AI Recommendations**: Click on any vulnerability to generate AI-powered fix recommendations

## API Documentation

Once the backend is running, access the interactive API docs at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Stopping Servers

```bash
./stop_servers.sh
```

## Troubleshooting

### Python Version Issues
Ensure you're using Python 3.10:
```bash
python --version  # Should show Python 3.10.x
```

### MongoDB Connection Issues
Check if MongoDB is running:
```bash
# macOS
brew services list | grep mongodb

# Linux
sudo systemctl status mongod
```

### Port Already in Use
If ports 3000 or 8000 are in use, modify:
- Backend: Change port in `start_servers.sh` and `backend/.env`
- Frontend: Set `PORT=3001` in `frontend/.env`

## Project Structure

```
FortKnoxx/
├── backend/              # FastAPI backend
│   ├── server.py        # Main application
│   ├── requirements.txt # Python dependencies
│   └── .env            # Backend configuration
├── frontend/            # React frontend
│   ├── src/
│   │   ├── App.js      # Main React components
│   │   └── components/ # UI components
│   ├── package.json    # Node dependencies
│   └── .env           # Frontend configuration
├── start_servers.sh    # Startup script
├── stop_servers.sh     # Shutdown script
└── README.md          # This file
```

## Security Notes

- Keep your `.env` files secure and never commit them to version control
- Use strong access tokens for repository access
- Run scans in a secure, isolated environment
- Review AI-generated fix recommendations before applying

## Contributing

This is a demonstration project. For production use, consider:
- Adding authentication and authorization
- Implementing rate limiting
- Setting up proper logging and monitoring
- Using a production WSGI server (e.g., Gunicorn)
- Implementing database backups

## License

[Add your license here]

## Support

For issues or questions, please [open an issue](https://github.com/your-repo/issues).

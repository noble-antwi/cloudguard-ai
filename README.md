# CloudGuard-AI 🛡️

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS](https://img.shields.io/badge/AWS-CloudTrail-orange.svg)](https://aws.amazon.com/cloudtrail/)

**AI-Powered AWS CloudTrail Threat Detection System**

An intelligent security monitoring system that uses machine learning to detect sophisticated threats in AWS CloudTrail logs, including privilege escalation, compromised credentials, and anomalous access patterns.

---

## 🎯 Overview

CloudGuard-AI analyzes AWS CloudTrail logs using machine learning to identify security threats that traditional rule-based systems miss. It combines unsupervised anomaly detection with supervised classification and AI-powered threat analysis.

### Key Features

- 🤖 **Machine Learning Detection**: Isolation Forest + Random Forest for threat identification
- 🧠 **AI-Powered Analysis**: Claude/GPT integration for human-readable threat explanations
- 📊 **Real-time Dashboard**: Streamlit-based monitoring interface
- 🔔 **Multi-channel Alerts**: Email, Slack, and AWS SNS notifications
- 🎯 **MITRE ATT&CK Mapping**: Automatic technique identification
- 📈 **Behavioral Analytics**: User and resource access pattern analysis

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- AWS Account with CloudTrail enabled
- AWS CLI configured

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cloudguard-ai.git
cd cloudguard-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure
```

### Run with Sample Data

```bash
# Generate sample CloudTrail logs
python scripts/generate_sample_data.py

# Train the model
python scripts/train_model.py

# Launch dashboard
streamlit run src/dashboard/app.py
```

---

## 📊 Architecture

```
CloudTrail Logs → Data Ingestion → Feature Engineering → ML Models
                                                             ↓
                  Dashboard ← Alert System ← Threat Analysis
```

**Components:**
- **Data Pipeline**: Ingests and preprocesses CloudTrail logs
- **Feature Engineering**: Extracts behavioral and contextual features
- **ML Engine**: Detects anomalies using Isolation Forest & Random Forest
- **Threat Analyzer**: AI-powered threat explanation and remediation
- **Alert System**: Multi-channel notification system
- **Dashboard**: Real-time monitoring interface

---

## 🔍 Threat Detection Capabilities

- ✅ Privilege escalation attempts
- ✅ Compromised credential detection
- ✅ Unusual geographic access patterns
- ✅ Mass API enumeration
- ✅ Data exfiltration indicators
- ✅ Insider threat detection
- ✅ Failed authentication patterns
- ✅ Dormant account reactivation

---

## 📁 Project Structure

```
cloudguard-ai/
├── src/
│   ├── data/               # Data ingestion and preprocessing
│   ├── models/             # ML model implementations
│   ├── analysis/           # Threat analysis and LLM integration
│   ├── alerting/           # Notification systems
│   └── dashboard/          # Streamlit web interface
├── notebooks/              # Jupyter notebooks for exploration
├── tests/                  # Unit and integration tests
├── configs/                # Configuration files
└── docs/                   # Documentation
```

---

## 🛠️ Configuration

Edit `configs/config.yaml`:

```yaml
aws:
  region: us-east-1
  cloudtrail_bucket: your-bucket-name

model:
  type: isolation_forest
  contamination: 0.1

alerting:
  enabled: true
  min_severity: medium
```

---

## 📈 Model Performance

| Metric | Value |
|--------|-------|
| Accuracy | 87.3% |
| Precision | 89.1% |
| Recall | 85.7% |
| F1-Score | 87.4% |

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/
```

---

## 📚 Documentation

- [Setup Guide](docs/setup.md)
- [Architecture](docs/architecture.md)
- [API Documentation](docs/api_documentation.md)
- [Model Performance](docs/model_performance.md)

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

---

## 👤 Author

**Noble W. Antwi**
- Cloud Security Engineer
- MS in Cybersecurity - Illinois Institute of Technology
- [LinkedIn](https://linkedin.com/in/noble-antwi-worlanyo)
- [Email](mailto:amnworlanyo@gmail.com)

---

## 🙏 Acknowledgments

- AWS CloudTrail for security logging
- MITRE ATT&CK Framework for threat taxonomy
- Anthropic Claude for AI analysis capabilities

---

**⭐ If you find this project useful, please give it a star!**
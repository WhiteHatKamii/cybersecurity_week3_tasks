# Week 3 Cybersecurity Tasks: Log Analysis, Firewall Configuration, Secure Coding, and More

## Overview
This repository contains detailed documentation and configurations for cybersecurity tasks completed during Week 3 of the internship. Each task is designed to enhance cybersecurity skills, including log analysis, firewall management, secure coding practices, web application testing, and basic malware analysis.

---

## Tasks Overview

### 1. Log Analysis and Security Event Monitoring
- **Objective**: Analyze logs to identify potential security incidents.
- **Tools Used**: Elastic Stack (Elasticsearch, Logstash, Kibana).
- **Steps**:

#### Commands:
```bash
sudo apt update && sudo apt upgrade
sudo bash -c "export HOSTNAME=kali-purple.kali.purple; apt-get install elasticsearch -y"

# Convert to single-node setup
sudo sed -e '/cluster.initial_master_nodes/ s/^#*/#/' -i /etc/elasticsearch/elasticsearch.yml

echo "discovery.type: single-node" | sudo tee -a /etc/elasticsearch/elasticsearch.yml

# Install Kibana
sudo apt install kibana
sudo /usr/share/kibana/bin/kibana-encryption-keys generate -q
sudo echo "server.host: \"kali-purple.kali.purple\"" | sudo tee -a /etc/kibana/kibana.yml

sudo systemctl enable elasticsearch kibana --now

# Enroll Kibana
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# Install Logstash
sudo apt install logstash -y
sudo systemctl start elasticsearch logstash kibana
sudo systemctl enable elasticsearch logstash kibana

# Configure Logstash for system logs
sudo nano /etc/logstash/conf.d/system-logs.conf

# Add Logstash configuration
input {
  file {
    path => "/var/log/auth.log"
    start_position => "beginning"
  }
}
output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "system-logs"
  }
}

sudo systemctl restart logstash
```

#### Deliverables:
-  Kibana dashboard showed suspicious login attempts and traffic anomalies.
- **Report**:
  - Identified 100+ failed SSH login attempts.
  - Unusual network traffic spike detected on port 8080, potentially indicating unauthorized scanning.

---

### 2. Firewall Configuration and Management
- **Objective**: Enhance network security using UFW.

#### Commands:
```bash
sudo apt install ufw -y
sudo ufw allow 22/tcp
sudo ufw deny 80/tcp
sudo ufw enable

# Verify UFW rules
sudo ufw status

# Test with nmap
nmap -p 22,80 localhost
```

#### Deliverables:
-  UFW configuration and nmap output.
- **Report**:
  - Rule allowing SSH only ensures secure administrative access.
  - Denying HTTP prevents unauthorized HTTP access.

---

### 3. Secure Web Application Testing
- **Objective**: Perform basic security assessments on a sample web application.
- **Tools Used**: DVWA (Damn Vulnerable Web Application).

#### Commands:
```bash
# Install prerequisites
sudo apt install apache2 php php-mysqli mysql-server -y

# Clone DVWA repository
git clone https://github.com/ethicalhack3r/DVWA.git /var/www/html/dvwa

# Configure DVWA
sudo mysql -u root -p
CREATE DATABASE dvwa;
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost' IDENTIFIED BY 'password';
FLUSH PRIVILEGES;
exit;

# Edit config.inc.php for database credentials

# Access DVWA setup
http://localhost/dvwa/setup.php
```

#### Deliverables:
 -  Successful SQL Injection and XSS exploitation.
- **Report**:
  - Vulnerabilities found: SQL Injection and XSS.
  - Recommendations: Input validation, parameterized queries, and sanitizing user inputs.

---

### 4. Malware Analysis Basics
- **Objective**: Understand malware behavior through static and dynamic analysis.
- **Tools Used**: Remnux, Wireshark.

#### Commands:
```bash
# Install Remnux
curl -sSL https://remnux.org/install | sudo bash

# Static analysis
strings malware_sample.exe > output.txt

# Dynamic analysis (use Wireshark for traffic monitoring)
```

#### Deliverables:
- **Remnux**: Remnux installation, `strings` output, and Wireshark traffic.
- **Report**:
  - Malware attempts to connect to malicious domains.
  - Recommendations: Block domains, monitor registry changes, and use AV solutions.

---

### 5. Secure Coding Practices
- **Objective**: Identify and fix insecure coding practices.

#### Commands:
**Original Code:**
```python
# Insecure script with hardcoded credentials
def connect_to_db():
    username = "admin"
    password = "password123"
    print("Connecting with:", username, password)
```

**Revised Code:**
```python
# Secure script with environment variables
def connect_to_db():
    import os
    username = os.getenv("DB_USERNAME")
    password = os.getenv("DB_PASSWORD")
    print("Connecting with:", username, "[PROTECTED]")
```

#### Deliverables:
- **Fixed Code**: Secure handling of credentials using environment variables.
- **Report**:
  - Issue: Hardcoded credentials risk exposure.
  - Fix: Use environment variables for secure management.

---

## Repository Structure
```plaintext
.
├── configurations/
│   ├── elasticsearch.yml
│   ├── kibana.yml
│   ├── logstash.conf
├── scripts/
│   ├── secure_script.py
├── Outputs/
│   ├── kibana_dashboard.png
│   ├── ufw_status.png
│   ├── nmap_output.png
│   ├── dvwa_tests.png
│   ├── malware_analysis.png
├── reports/
│   ├── log_analysis_report.pdf
│   ├── firewall_configuration_report.pdf
│   ├── web_app_testing_report.pdf
│   ├── malware_analysis_report.pdf
│   ├── secure_coding_report.pdf
├── README.md
```

---

## Getting Started

### Clone the Repository
```bash
git clone https://github.com/yourusername/week3-cybersecurity-tasks.git
cd week3-cybersecurity-tasks
```

### Setup and Configuration
Follow the steps documented in each task folder (`/configurations` or `/scripts`) to reproduce the setups and configurations.


---

## Contact
For any questions or clarifications, please contact me at kb043009@gmail.com.

# Shammah - GitHub Repo Scanning Service

Web interface for the $2/scan GitHub repository security scanning service.

## Overview

This service allows users to scan any public GitHub repository for security vulnerabilities for $2 per scan. This creates an additional revenue stream separate from the main subscription model.

## Features

- Simple web interface for submitting GitHub repository URLs
- Payment processing for $2 per scan
- Security scanning of public repositories
- Detailed vulnerability reports

## Architecture

- **Frontend**: Simple Flask web interface
- **Backend**: Security scanning using the same engine as the Shammah server
- **Payment**: Integration with payment processor (simulated in demo)

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the server:
   ```
   python app.py
   ```

3. Access the interface at `http://localhost:5000`

## How It Works

1. User submits a GitHub repository URL
2. Payment of $2 is processed
3. Repository is cloned and scanned for security vulnerabilities
4. Detailed report is generated and presented to the user

## API Endpoints

- `GET /` - Main web interface
- `POST /api/scan` - Scan a repository
- `POST /api/process-payment` - Process payment for a scan

## Security

- Only public repositories are scanned
- Temporary directories are cleaned up after scanning
- No sensitive data is stored permanently

## Revenue Model

- $2 per repository scan
- Separate from main subscription model
- Pay-per-use pricing

## Future Enhancements

- Bulk scanning for multiple repositories
- Scheduled scanning for continuous monitoring
- Integration with CI/CD pipelines
- Detailed fix recommendations
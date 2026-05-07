"""
Simple Web Interface for GitHub Repo Scanning
Flask-based API for the $2/scan service
"""
from flask import Flask, request, jsonify, render_template_string
import os
from services.github_repo_scanner import GitHubRepoScanner

app = Flask(__name__)
scanner = GitHubRepoScanner()

# Simple HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security MCP - GitHub Repo Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        input[type="text"] { width: 100%; padding: 10px; margin: 10px 0; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .result { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security MCP - GitHub Repo Scanner</h1>
        <p>Scan any public GitHub repository for security vulnerabilities. Cost: $2 per scan.</p>
        
        <form id="scanForm">
            <label for="repoUrl">GitHub Repository URL:</label>
            <input type="text" id="repoUrl" name="repoUrl" placeholder="https://github.com/username/repository" required>
            <button type="submit">Scan Repository ($2)</button>
        </form>
        
        <div id="result"></div>
    </div>

    <script>
        document.getElementById('scanForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const repoUrl = document.getElementById('repoUrl').value;
            const resultDiv = document.getElementById('result');
            
            resultDiv.innerHTML = '<p class="success">Processing your scan request...</p>';
            
            try {
                // In a real implementation, this would go through a payment processor
                // For demo, we'll simulate the payment and scan
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ repo_url: repoUrl })
                });
                
                const data = await response.json();
                
                if (data.error) {
                    resultDiv.innerHTML = `<div class="result error"><strong>Error:</strong> ${data.error}</div>`;
                } else {
                    resultDiv.innerHTML = `
                        <div class="result">
                            <h3>Scan Results for ${repoUrl}</h3>
                            <p><strong>Files Scanned:</strong> ${data.files_scanned}</p>
                            <p><strong>Issues Found:</strong> ${data.issues_found}</p>
                            <p><strong>Issues by Severity:</strong></p>
                            <ul>
                                <li>Critical: ${data.issues_by_severity.critical}</li>
                                <li>High: ${data.issues_by_severity.high}</li>
                                <li>Medium: ${data.issues_by_severity.medium}</li>
                                <li>Low: ${data.issues_by_severity.low}</li>
                            </ul>
                            <p><em>Full report would include detailed findings and fix suggestions.</em></p>
                        </div>
                    `;
                }
            } catch (error) {
                resultDiv.innerHTML = `<div class="result error"><strong>Error:</strong> ${error.message}</div>`;
            }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Render the main page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan', methods=['POST'])
def scan_repo():
    """API endpoint to scan a GitHub repository"""
    try:
        data = request.json
        repo_url = data.get('repo_url')
        
        if not repo_url:
            return jsonify({'error': 'Repository URL is required'}), 400
        
        # In a real implementation, this is where we would:
        # 1. Process payment ($2)
        # 2. Validate the repo exists
        # 3. Perform the actual scan
        
        # For this demo, we'll simulate a scan
        # In reality, we'd call scanner.scan_github_repo(repo_url)
        results = {
            'repo_url': repo_url,
            'files_scanned': 24,  # Simulated
            'issues_found': 3,    # Simulated
            'issues_by_severity': {
                'critical': 0,
                'high': 1,
                'medium': 2,
                'low': 0
            },
            'payment_processed': True,
            'cost': 2.00
        }
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/process-payment', methods=['POST'])
def process_payment():
    """API endpoint to process payment for a scan"""
    try:
        data = request.json
        amount = data.get('amount', 0)
        repo_url = data.get('repo_url')
        
        if amount != 2.00:
            return jsonify({'error': 'Incorrect amount for repository scan'}), 400
        
        if not repo_url:
            return jsonify({'error': 'Repository URL is required'}), 400
        
        # In a real implementation, this would process the payment
        # using a payment processor like Stripe
        
        return jsonify({
            'status': 'success',
            'message': 'Payment processed successfully',
            'transaction_id': 'txn_' + os.urandom(8).hex()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
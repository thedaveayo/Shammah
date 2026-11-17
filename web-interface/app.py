"""
Shammah Web Interface
A small local web page for scanning a public GitHub repository.

Run it on your own machine:  python app.py  ->  http://127.0.0.1:5000
"""
import os
import sys

from flask import Flask, request, jsonify, render_template_string

# The scanner lives in the MCP server package
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mcp-server"))
from services.github_repo_scanner import GitHubRepoScanner  # noqa: E402

app = Flask(__name__)
scanner = GitHubRepoScanner()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Shammah - GitHub Repo Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        input[type="text"] { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .result { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Shammah - GitHub Repo Scanner</h1>
        <p>Scan a public GitHub repository for security vulnerabilities.</p>

        <form id="scanForm">
            <label for="repoUrl">GitHub Repository URL:</label>
            <input type="text" id="repoUrl" name="repoUrl" placeholder="https://github.com/username/repository" required>
            <button type="submit">Scan Repository</button>
        </form>

        <div id="result"></div>
    </div>

    <script>
        function el(tag, text, cls) {
            const node = document.createElement(tag);
            if (text !== undefined) node.textContent = text;
            if (cls) node.className = cls;
            return node;
        }

        document.getElementById('scanForm').addEventListener('submit', async function(e) {
            e.preventDefault();

            const repoUrl = document.getElementById('repoUrl').value;
            const resultDiv = document.getElementById('result');
            resultDiv.replaceChildren(el('p', 'Scanning... this can take a minute for large repositories.', 'success'));

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ repo_url: repoUrl })
                });
                const data = await response.json();

                if (data.error) {
                    resultDiv.replaceChildren(el('div', 'Error: ' + data.error, 'result error'));
                    return;
                }

                const box = el('div', undefined, 'result');
                box.append(el('h3', 'Scan results for ' + repoUrl));
                box.append(el('p', 'Files scanned: ' + data.files_scanned));
                box.append(el('p', 'Issues found: ' + data.issues_found));
                const sev = el('ul');
                for (const level of ['critical', 'high', 'medium', 'low']) {
                    sev.append(el('li', level + ': ' + data.issues_by_severity[level]));
                }
                box.append(sev);
                if (data.issues && data.issues.length) {
                    const list = el('ol');
                    for (const issue of data.issues.slice(0, 200)) {
                        list.append(el('li', '[' + issue.severity + '] ' + issue.file_path + ' - ' + issue.title));
                    }
                    box.append(list);
                }
                resultDiv.replaceChildren(box);
            } catch (error) {
                resultDiv.replaceChildren(el('div', 'Error: ' + error.message, 'result error'));
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
    """Scan a public GitHub repository"""
    data = request.get_json(silent=True) or {}
    repo_url = (data.get('repo_url') or '').strip()

    if not repo_url:
        return jsonify({'error': 'Repository URL is required'}), 400

    try:
        results = scanner.scan_github_repo(repo_url)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        app.logger.exception("Scan failed")
        return jsonify({'error': 'Scan failed. Check that the repository exists and is public.'}), 500

    results.pop('repo_path', None)  # don't expose local temp paths
    return jsonify(results)


if __name__ == '__main__':
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', '5000'))
    app.run(host=host, port=port, debug=False)

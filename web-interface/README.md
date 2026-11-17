# Shammah - Web Interface

A small local web page for scanning a public GitHub repository with the same
engine the Shammah MCP server uses.

## Setup

```bash
pip install -r requirements.txt -r ../mcp-server/requirements.txt
python app.py
```

Open http://127.0.0.1:5000, paste a public `https://github.com/owner/repo` URL and
press **Scan Repository**. Git must be installed, because the repository is cloned
to a temporary folder, scanned, then deleted.

## Notes

- The server listens on `127.0.0.1` by default. Set `HOST` and `PORT` to change that.
- Only `https://github.com/...` URLs are accepted.
- This page has no login. Don't expose it to the internet without putting
  authentication and rate limiting in front of it, since every scan clones a repository.

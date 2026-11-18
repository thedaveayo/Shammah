"""
Test setup: use a throwaway database and never contact a real backend.
This runs before any test module imports the server's config.
"""
import os
import sys
import tempfile

MCP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MCP_DIR)

_tmp = tempfile.mkdtemp(prefix="shammah-tests-")
TEST_DB_PATH = os.path.join(_tmp, "test.db")
os.environ["DATABASE_URL"] = "sqlite:///" + TEST_DB_PATH.replace("\\", "/")
os.environ["AUTO_SYNC_ON_START"] = "false"
os.environ["BACKEND_URL"] = "http://127.0.0.1:9"  # nothing listens here

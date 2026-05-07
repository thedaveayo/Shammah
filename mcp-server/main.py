"""
Security MCP Server
Main entry point for MCP server for coding agents
"""
import asyncio
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp_server import SecurityMCPServer

def main():
    """Run the Security MCP server for coding agents"""
    server = SecurityMCPServer()
    server.run_sync("localhost", 8080)

if __name__ == "__main__":
    main()

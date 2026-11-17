"""
Security MCP Server
Model Context Protocol (MCP) Server for coding agents
Provides real-time security scanning for code as it's being written
"""
import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from mcp.server import Server
from mcp.types import Tool, TextContent
import sys
import os

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import necessary modules
from services.security_scanner import SecurityScanner
from services.code_change_tracker import CodeChangeTracker

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityMCPServer:
    """Main MCP server for security enforcement in coding agents"""
    
    def __init__(self):
        self.server = Server()
        self.scanner = SecurityScanner()
        self.tracker = CodeChangeTracker()
        
        # Register all MCP tools
        self._register_tools()
    
    def _register_tools(self):
        """Register MCP tools for coding agents"""
        
        @self.server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="scan_code_block",
                    description="Scan a code block for security vulnerabilities after generation",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "code_block": {
                                "type": "string",
                                "description": "Code to scan for vulnerabilities"
                            },
                            "language": {
                                "type": "string",
                                "description": "Programming language of the code"
                            },
                            "context": {
                                "type": "string",
                                "description": "Context where the code will be used (e.g., backend, frontend, mobile)"
                            }
                        },
                        "required": ["code_block", "language"]
                    }
                ),
                Tool(
                    name="get_security_report",
                    description="Get a detailed security report for the current project",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "project_path": {
                                "type": "string",
                                "description": "Path to the project to analyze"
                            },
                            "report_type": {
                                "type": "string",
                                "enum": ["summary", "detailed", "fixes"],
                                "description": "Type of report to generate"
                            }
                        },
                        "required": ["project_path"]
                    }
                ),
                Tool(
                    name="get_fix_suggestions",
                    description="Get specific fix suggestions for identified security issues",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "code_block": {
                                "type": "string",
                                "description": "Code with security issues"
                            },
                            "vulnerability_types": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Types of vulnerabilities to focus on (optional)"
                            }
                        },
                        "required": ["code_block"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict):
            """Handle tool calls from the coding agent"""
            logger.info(f"Received tool call: {name}")
            
            if name == "scan_code_block":
                return await self._scan_code_block(arguments)
            elif name == "get_security_report":
                return await self._get_security_report(arguments)
            elif name == "get_fix_suggestions":
                return await self._get_fix_suggestions(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
    
    async def _scan_code_block(self, arguments: dict):
        """Scan a code block for security vulnerabilities"""
        code_block = arguments.get("code_block", "")
        language = arguments.get("language", "unknown")
        context = arguments.get("context", "unknown")
        
        if not code_block:
            return [TextContent(type="text", text="Error: No code block provided")]
        
        # Perform security scan
        scan_results = self.scanner.scan_code_block(code_block, language, context)
        
        # Track the code change
        self.tracker.record_code_change(code_block, language, scan_results)
        
        # Format results
        if not scan_results["issues"]:
            result_text = "✓ No security vulnerabilities detected in the provided code block."
        else:
            result_text = f"⚠ Found {len(scan_results['issues'])} potential security vulnerability(ies):\n\n"
            for i, issue in enumerate(scan_results["issues"], 1):
                result_text += f"{i}. {issue['title']} ({issue['severity'].upper()}):\n"
                result_text += f"   - {issue['description']}\n"
                result_text += f"   - Recommendation: {issue['recommendation']}\n\n"
        
        result_text += f"\nScanned {len(scan_results['lines'])} lines of {language} code."
        
        return [TextContent(type="text", text=result_text)]
    
    async def _get_security_report(self, arguments: dict):
        """Get a detailed security report for the project"""
        project_path = arguments.get("project_path", "")
        report_type = arguments.get("report_type", "summary")
        
        # Generate report
        report = self.scanner.generate_project_report(project_path, report_type)
        
        return [TextContent(type="text", text=report)]
    
    async def _get_fix_suggestions(self, arguments: dict):
        """Get specific fix suggestions for security issues"""
        code_block = arguments.get("code_block", "")
        vulnerability_types = arguments.get("vulnerability_types", [])
        
        if not code_block:
            return [TextContent(type="text", text="Error: No code block provided")]
        
        # Get fix suggestions
        suggestions = self.scanner.get_fix_suggestions(code_block, vulnerability_types)
        
        if not suggestions:
            result_text = "No specific fix suggestions available for the provided code."
        else:
            result_text = f"Fix suggestions for {len(suggestions)} issue(s):\n\n"
            for i, suggestion in enumerate(suggestions, 1):
                result_text += f"{i}. {suggestion['title']}:\n"
                result_text += f"   - Issue: {suggestion['issue']}\n"
                result_text += f"   - Fix: {suggestion['fix']}\n\n"
        
        return [TextContent(type="text", text=result_text)]
    
    async def start_server(self, host: str = "localhost", port: int = 8080):
        """Start the MCP server"""
        logger.info(f"Starting Security MCP server on {host}:{port}")
        
        # Start the server
        await self.server.run_tcp(host, port)
    
    def run_sync(self, host: str = "localhost", port: int = 8080):
        """Run the server synchronously"""
        async def run():
            await self.start_server(host, port)
        
        asyncio.run(run())


if __name__ == "__main__":
    server = SecurityMCPServer()
    server.run_sync()
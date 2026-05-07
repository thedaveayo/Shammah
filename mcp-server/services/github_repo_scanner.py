"""
GitHub Repository Scanning Service
Allows users to scan GitHub repositories for security issues
"""
import os
import requests
import tempfile
import subprocess
import shutil
from typing import Dict, List, Optional
from urllib.parse import urlparse
import json
from datetime import datetime
from services.security_scanner import SecurityScanner


class GitHubRepoScanner:
    """Service for scanning GitHub repositories"""
    
    def __init__(self):
        self.scanner = SecurityScanner()
        self.temp_dirs = []
    
    def _validate_github_url(self, url: str) -> bool:
        """Validate that the URL is a valid GitHub repository URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc in ['github.com', 'www.github.com'] and len(parsed.path.split('/')) >= 3
        except Exception:
            return False
    
    def _clone_repository(self, repo_url: str) -> str:
        """Clone a GitHub repository to a temporary directory"""
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        self.temp_dirs.append(temp_dir)
        
        try:
            # Clone the repository
            result = subprocess.run([
                'git', 'clone', repo_url, temp_dir
            ], capture_output=True, text=True, check=True)
            
            return temp_dir
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to clone repository: {e.stderr}")
    
    def _scan_directory(self, directory_path: str) -> Dict:
        """Scan a directory for security issues"""
        results = {
            'repo_path': directory_path,
            'scan_time': datetime.utcnow().isoformat(),
            'files_scanned': 0,
            'issues_found': 0,
            'issues_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'issues': []
        }
        
        # Walk through the directory
        for root, dirs, files in os.walk(directory_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'dist', 'build']]
            
            for file in files:
                # Only scan source code files
                if self._is_source_file(file):
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            code_content = f.read()
                        
                        # Determine language from file extension
                        language = self._get_language_from_extension(file)
                        
                        # Scan the code
                        scan_result = self.scanner.scan_code_block(code_content, language)
                        
                        if scan_result['issues']:
                            results['issues_found'] += len(scan_result['issues'])
                            
                            for issue in scan_result['issues']:
                                # Add file path to the issue
                                issue['file_path'] = os.path.relpath(file_path, directory_path)
                                results['issues'].append(issue)
                                
                                # Update severity counts
                                severity = issue['severity'].lower()
                                if severity in results['issues_by_severity']:
                                    results['issues_by_severity'][severity] += 1
                        
                        results['files_scanned'] += 1
                    except Exception as e:
                        print(f"Error scanning file {file_path}: {e}")
        
        return results
    
    def _is_source_file(self, filename: str) -> bool:
        """Check if a file is a source code file"""
        source_extensions = {
            '.js', '.ts', '.jsx', '.tsx',  # JavaScript/TypeScript
            '.py',  # Python
            '.java',  # Java
            '.go',  # Go
            '.php',  # PHP
            '.rb',  # Ruby
            '.cs',  # C#
            '.cpp', '.cxx', '.c', '.h',  # C/C++
            '.rs',  # Rust
            '.scala',  # Scala
            '.kt', '.kts',  # Kotlin
            '.swift',  # Swift
            '.dart',  # Dart
            '.sql',  # SQL
            '.sh',  # Shell
            '.pl', '.pm',  # Perl
            '.R',  # R
            '.lua',  # Lua
            '.m', '.mm',  # Objective-C
        }
        
        _, ext = os.path.splitext(filename)
        return ext.lower() in source_extensions
    
    def _get_language_from_extension(self, filename: str) -> str:
        """Get programming language from file extension"""
        ext_map = {
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.py': 'python',
            '.java': 'java',
            '.go': 'go',
            '.php': 'php',
            '.rb': 'ruby',
            '.cs': 'csharp',
            '.cpp': 'c++',
            '.cxx': 'c++',
            '.c': 'c',
            '.h': 'c',
            '.rs': 'rust',
            '.scala': 'scala',
            '.kt': 'kotlin',
            '.kts': 'kotlin',
            '.swift': 'swift',
            '.dart': 'dart',
            '.sql': 'sql',
            '.sh': 'shell',
            '.pl': 'perl',
            '.pm': 'perl',
            '.R': 'r',
            '.lua': 'lua',
            '.m': 'objectivec',
            '.mm': 'objectivec',
        }
        
        _, ext = os.path.splitext(filename)
        return ext_map.get(ext.lower(), 'unknown')
    
    def scan_github_repo(self, repo_url: str) -> Dict:
        """Scan a GitHub repository for security issues"""
        if not self._validate_github_url(repo_url):
            raise ValueError(f"Invalid GitHub URL: {repo_url}")
        
        print(f"Starting scan of repository: {repo_url}")
        
        # Clone the repository
        repo_dir = self._clone_repository(repo_url)
        print(f"Repository cloned to: {repo_dir}")
        
        # Scan the repository
        results = self._scan_directory(repo_dir)
        
        # Cleanup: Remove the temporary directory
        try:
            shutil.rmtree(repo_dir)
            self.temp_dirs.remove(repo_dir)
        except Exception as e:
            print(f"Warning: Could not remove temporary directory {repo_dir}: {e}")
        
        print(f"Scan completed. Files scanned: {results['files_scanned']}, Issues found: {results['issues_found']}")
        
        return results
    
    def cleanup_temp_dirs(self):
        """Clean up all temporary directories created during scanning"""
        for temp_dir in self.temp_dirs:
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                print(f"Warning: Could not remove temporary directory {temp_dir}: {e}")
        
        self.temp_dirs.clear()


# Example usage
if __name__ == "__main__":
    scanner = GitHubRepoScanner()
    
    try:
        # Example repository scan
        repo_url = "https://github.com/example/repo"  # Replace with actual URL
        results = scanner.scan_github_repo(repo_url)
        
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        scanner.cleanup_temp_dirs()
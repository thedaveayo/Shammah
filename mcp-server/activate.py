"""
Activation Script for Security MCP
Sets up subscription token for the MCP server
"""
import os
import sys
import argparse
from pathlib import Path

def activate_subscription(token: str, user_id: str = None):
    """Activate subscription with the provided token"""
    
    # Validate token format (basic check)
    if not token or len(token) < 10:
        print("Error: Invalid token format")
        return False
    
    # Update the .env file with the new token
    env_file = Path(".env")
    
    # Read existing content
    if env_file.exists():
        content = env_file.read_text()
    else:
        content = ""
    
    # Check if AUTH_TOKEN already exists in the file
    lines = content.splitlines()
    token_line_exists = any(line.strip().startswith("AUTH_TOKEN=") for line in lines)
    
    if token_line_exists:
        # Update existing AUTH_TOKEN line
        updated_lines = []
        for line in lines:
            if line.strip().startswith("AUTH_TOKEN="):
                updated_lines.append(f"AUTH_TOKEN={token}")
            else:
                updated_lines.append(line)
        content = "\n".join(updated_lines)
    else:
        # Add new AUTH_TOKEN line
        if content and not content.endswith('\n'):
            content += "\n"
        content += f"AUTH_TOKEN={token}\n"
    
    # Write updated content back to file
    with open(env_file, "w") as f:
        f.write(content)
    
    print(f"✓ Subscription activated for token: {token[:10]}...")
    
    if user_id:
        print(f"✓ User ID set to: {user_id}")
    
    print("\nSecurity MCP is now ready to use!")
    print("Start the server with: python main.py")
    
    return True

def main():
    parser = argparse.ArgumentParser(description="Activate Security MCP subscription")
    parser.add_argument("--token", required=True, help="Subscription token")
    parser.add_argument("--user-id", required=False, help="User ID (optional)")
    
    args = parser.parse_args()
    
    success = activate_subscription(args.token, args.user_id)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
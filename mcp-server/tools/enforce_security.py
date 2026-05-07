"""
MCP Tools - Exposed to IDE Coding Agent
Security enforcement tools
"""
from mcp.server import Server
from mcp.types import Tool, TextContent
import sys
import os

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def register_tools(server: Server, get_db_func):
    """Register MCP tools"""
    
    @server.list_tools()
    async def list_tools():
        return [
            Tool(
                name="enforce_security",
                description="Validate code against security rules. Returns violations that must be fixed before proceeding.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Code to validate"
                        },
                        "language": {
                            "type": "string",
                            "description": "Programming language (optional)"
                        }
                    },
                    "required": ["code"]
                }
            ),
            Tool(
                name="security_scan_file",
                description="Scan a specific file for security vulnerabilities",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to scan"
                        },
                        "include_details": {
                            "type": "boolean",
                            "description": "Whether to include detailed information about vulnerabilities (default: false)"
                        }
                    },
                    "required": ["file_path"]
                }
            ),
            Tool(
                name="security_fix_suggestions",
                description="Get specific fix suggestions for security vulnerabilities in code",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Code that contains security issues"
                        },
                        "language": {
                            "type": "string",
                            "description": "Programming language of the code"
                        },
                        "vulnerability_type": {
                            "type": "string",
                            "description": "Type of vulnerability to focus on (optional)"
                        }
                    },
                    "required": ["code"]
                }
            ),
            Tool(
                name="security_context_explain",
                description="Explain security context and implications of code in plain English",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Code to analyze for security context"
                        },
                        "language": {
                            "type": "string",
                            "description": "Programming language of the code"
                        },
                        "audience": {
                            "type": "string",
                            "description": "Target audience for explanation (developer, manager, security-expert) - default: developer"
                        }
                    },
                    "required": ["code"]
                }
            ),
            Tool(
                name="security_rule_details",
                description="Get detailed information about a specific security rule",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "rule_id": {
                            "type": "string",
                            "description": "ID of the rule to get details for"
                        },
                        "include_examples": {
                            "type": "boolean",
                            "description": "Whether to include code examples (default: false)"
                        }
                    },
                    "required": ["rule_id"]
                }
            ),
            Tool(
                name="get_compliance_status",
                description="Get current security compliance status of the project",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "project_path": {
                            "type": "string",
                            "description": "Path to project directory"
                        }
                    }
                }
            ),
            Tool(
                name="acknowledge_fix",
                description="Acknowledge that a security violation has been fixed",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "violation_id": {
                            "type": "string",
                            "description": "Rule ID of the violation"
                        },
                        "fix_description": {
                            "type": "string",
                            "description": "Description of how the issue was fixed"
                        }
                    },
                    "required": ["violation_id", "fix_description"]
                }
            ),
            Tool(
                name="get_infrastructure_profile",
                description="Detect project infrastructure (languages, frameworks, etc.)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "project_path": {
                            "type": "string",
                            "description": "Path to project directory"
                        }
                    },
                    "required": ["project_path"]
                }
            ),
            Tool(
                name="sync_rules",
                description="Sync latest security rules from backend (requires active subscription)",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]
    
    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        """Handle tool calls"""
        db = next(get_db_func())

        try:
            if name == "enforce_security":
                return await enforce_security(db, arguments)
            elif name == "security_scan_file":
                return await security_scan_file(db, arguments)
            elif name == "security_fix_suggestions":
                return await security_fix_suggestions(db, arguments)
            elif name == "security_context_explain":
                return await security_context_explain(db, arguments)
            elif name == "security_rule_details":
                return await security_rule_details(db, arguments)
            elif name == "get_compliance_status":
                return get_compliance_status(db, arguments)
            elif name == "acknowledge_fix":
                return acknowledge_fix(db, arguments)
            elif name == "get_infrastructure_profile":
                return get_infrastructure_profile(db, arguments)
            elif name == "sync_rules":
                return sync_rules(db, arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
        finally:
            db.close()

async def enforce_security(db, arguments: dict):
    """Validate code against security rules"""
    from models.rule import LocalRule
    from services.pattern_matcher import PatternMatcher
    from services.subscription import LocalSubscriptionManager
    from services.enforcer import Enforcer

    code = arguments.get("code", "")

    # Get subscription
    sub_manager = LocalSubscriptionManager(db)
    subscription = sub_manager.get_subscription()

    # Get rules
    rules = db.query(LocalRule).all()

    # Enforce
    enforcer = Enforcer()
    result = enforcer.enforce(code, rules, subscription)

    return [TextContent(
        type="text",
        text=str(result)
    )]

async def security_scan_file(db, arguments: dict):
    """Scan a specific file for security vulnerabilities"""
    from models.rule import LocalRule
    from services.pattern_matcher import PatternMatcher
    from services.subscription import LocalSubscriptionManager
    from services.enforcer import Enforcer
    import os

    file_path = arguments.get("file_path", "")
    include_details = arguments.get("include_details", False)

    # Verify file exists
    if not os.path.exists(file_path):
        return [TextContent(
            type="text",
            text=f"Error: File does not exist: {file_path}"
        )]

    # Read the file content
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error reading file: {str(e)}"
        )]

    # Get subscription
    sub_manager = LocalSubscriptionManager(db)
    subscription = sub_manager.get_subscription()

    # Get rules
    rules = db.query(LocalRule).all()

    # Use PatternMatcher directly to get detailed results
    matcher = PatternMatcher()
    violations = matcher.match(code, rules)

    # Format results
    if not violations:
        result_text = f"✓ No security vulnerabilities found in {file_path}"
    else:
        result_text = f"⚠ Found {len(violations)} potential security vulnerability(ies) in {file_path}:\n\n"
        for i, (rule, matched_text) in enumerate(violations, 1):
            result_text += f"{i}. {rule.title} ({rule.severity.upper()}):\n"
            result_text += f"   Description: {rule.description}\n"
            if include_details:
                result_text += f"   Matched code: {matched_text[:100]}{'...' if len(matched_text) > 100 else ''}\n"
                result_text += f"   Rule ID: {rule.rule_id}\n"
                result_text += f"   References: {', '.join(rule.cve_refs + rule.cwe_refs)}\n"
            result_text += "\n"

    return [TextContent(
        type="text",
        text=result_text
    )]

async def security_fix_suggestions(db, arguments: dict):
    """Get specific fix suggestions for security vulnerabilities in code"""
    from models.rule import LocalRule
    from services.pattern_matcher import PatternMatcher
    import re

    code = arguments.get("code", "")
    language = arguments.get("language", "").lower()
    vulnerability_type = arguments.get("vulnerability_type", "").lower()

    # Get all rules
    rules = db.query(LocalRule).all()

    # Use PatternMatcher to find violations
    matcher = PatternMatcher()
    violations = matcher.match(code, rules)

    # Generate fix suggestions
    suggestions = []
    
    for rule, matched_text in violations:
        # Only process if vulnerability type matches or no specific type requested
        if not vulnerability_type or vulnerability_type in rule.title.lower() or vulnerability_type in rule.description.lower():
            # Generate specific fix based on rule type and language
            fix_suggestion = generate_fix_suggestion(code, rule, language)
            if fix_suggestion:
                suggestions.append({
                    'rule_title': rule.title,
                    'severity': rule.severity,
                    'description': rule.description,
                    'fix_suggestion': fix_suggestion,
                    'matched_code': matched_text
                })

    # Format results
    if not suggestions:
        result_text = "No specific fix suggestions available for the provided code."
    else:
        result_text = f"Fix suggestions for {len(suggestions)} vulnerability(ies):\n\n"
        for i, suggestion in enumerate(suggestions, 1):
            result_text += f"{i}. {suggestion['rule_title']} ({suggestion['severity'].upper()}):\n"
            result_text += f"   Issue: {suggestion['description']}\n"
            result_text += f"   Fix: {suggestion['fix_suggestion']}\n"
            if suggestion['matched_code']:
                result_text += f"   Problematic code: {suggestion['matched_code'][:100]}{'...' if len(suggestion['matched_code']) > 100 else ''}\n"
            result_text += "\n"

    return [TextContent(
        type="text",
        text=result_text
    )]

def generate_fix_suggestion(code: str, rule, language: str):
    """Generate specific fix suggestions based on the rule and language"""
    rule_title = rule.title.lower()
    rule_desc = rule.description.lower()
    
    # Common security fixes based on vulnerability type
    if 'injection' in rule_title or 'injection' in rule_desc:
        if language == 'javascript':
            return ("Sanitize user inputs before using them in dynamic operations. "
                    "Use parameterized queries or prepared statements. "
                    "Validate and escape all user inputs.")
        elif language == 'python':
            return ("Use parameterized queries or prepared statements. "
                    "Validate and sanitize all user inputs before processing. "
                    "Avoid using eval() or exec() with user inputs.")
    elif 'xss' in rule_title or 'cross site scripting' in rule_desc:
        if language == 'javascript':
            return ("Always sanitize user-generated content before inserting it into the DOM. "
                    "Use frameworks that automatically escape content (like React). "
                    "Use methods like textContent instead of innerHTML when possible.")
        elif language == 'python':
            return ("Use template engines that automatically escape content. "
                    "Manually escape HTML entities when displaying user-generated content. "
                    "Implement Content Security Policy (CSP) headers.")
    elif 'hardcoded' in rule_title or 'credential' in rule_desc:
        return ("Move credentials to environment variables or a secure configuration management system. "
                "Never store credentials directly in source code. "
                "Use a secrets management solution for production environments.")
    elif 'path traversal' in rule_title or 'directory traversal' in rule_desc:
        if language == 'javascript':
            return ("Validate and sanitize file paths before accessing the filesystem. "
                    "Use path normalization functions and restrict access to specific directories. "
                    "Consider using allowlists for file extensions and paths.")
        elif language == 'python':
            return ("Use os.path.abspath() and os.path.realpath() to resolve paths. "
                    "Compare resolved paths against allowed directories. "
                    "Use allowlists for file extensions and validate file paths.")
    elif 'deserialization' in rule_title or 'unsafe deserialization' in rule_desc:
        return ("Use safe deserialization methods that validate types and structures. "
                "Implement allowlists for acceptable classes/types during deserialization. "
                "Consider using safer data formats like JSON instead of native serialization.")
    elif 'permission' in rule_title or 'privilege' in rule_desc:
        return ("Implement proper authorization checks for all sensitive operations. "
                "Apply principle of least privilege - grant minimum necessary permissions. "
                "Regularly review and audit permission assignments.")
    
    # Default generic suggestion
    return ("Review the security rule details and implement appropriate mitigations. "
            "Follow security best practices for your technology stack. "
            "Consider consulting security documentation or experts for complex issues.")

async def security_context_explain(db, arguments: dict):
    """Explain security context and implications of code in plain English"""
    from models.rule import LocalRule
    from services.pattern_matcher import PatternMatcher
    import re

    code = arguments.get("code", "")
    language = arguments.get("language", "").lower()
    audience = arguments.get("audience", "developer").lower()

    # Get all rules
    rules = db.query(LocalRule).all()

    # Use PatternMatcher to find potential issues
    matcher = PatternMatcher()
    violations = matcher.match(code, rules)

    # Analyze the code for security context
    context_analysis = analyze_security_context(code, language, audience, violations)

    return [TextContent(
        type="text",
        text=context_analysis
    )]

def analyze_security_context(code: str, language: str, audience: str, violations):
    """Analyze code for security context and generate explanation"""
    # Determine the appropriate level of detail based on audience
    if audience == "manager":
        # Provide high-level summary without technical details
        if violations:
            return (f"This code contains {len(violations)} potential security issues that could impact business operations. "
                    f"It's recommended to have a security expert review this code before deployment to mitigate potential risks "
                    f"to customer data and company assets.")
        else:
            return "Initial analysis shows no major security concerns with this code, but a thorough review is still recommended."
    elif audience == "security-expert":
        # Provide detailed technical analysis
        analysis = "Security Context Analysis:\n\n"
        
        if violations:
            analysis += f"Detected {len(violations)} potential vulnerabilities:\n"
            for i, (rule, matched_text) in enumerate(violations, 1):
                analysis += f"{i}. {rule.title} ({rule.severity.upper()}):\n"
                analysis += f"   - Description: {rule.description}\n"
                analysis += f"   - Impact: Potential for {rule.enforcement.get('message', 'unknown impact')}\n"
                analysis += f"   - Matched code snippet: {matched_text[:100]}{'...' if len(matched_text) > 100 else ''}\n\n"
        else:
            analysis += "No specific vulnerabilities detected by current rule set.\n"
        
        # Additional security patterns analysis
        analysis += "Additional Security Patterns Observed:\n"
        
        # Check for authentication/authorization patterns
        auth_patterns = ["auth", "login", "permission", "role", "acl", "rbac"]
        found_auth = [pat for pat in auth_patterns if re.search(rf'\b{pat}\b', code, re.IGNORECASE)]
        if found_auth:
            analysis += f"- Authentication/Authorization: Found references to {', '.join(found_auth)}\n"
        
        # Check for data handling
        data_patterns = ["encrypt", "decrypt", "hash", "password", "credential", "token"]
        found_data = [pat for pat in data_patterns if re.search(rf'\b{pat}\b', code, re.IGNORECASE)]
        if found_data:
            analysis += f"- Data Handling: Found references to {', '.join(found_data)}\n"
        
        # Check for network operations
        net_patterns = ["socket", "connect", "request", "http", "tcp", "udp"]
        found_net = [pat for pat in net_patterns if re.search(rf'\b{pat}\b', code, re.IGNORECASE)]
        if found_net:
            analysis += f"- Network Operations: Found references to {', '.join(found_net)}\n"
        
        return analysis
    else:  # developer (default)
        # Provide developer-focused explanation with actionable insights
        if violations:
            explanation = f"The following code contains {len(violations)} potential security vulnerabilities:\n\n"
            for i, (rule, matched_text) in enumerate(violations, 1):
                explanation += f"{i}. {rule.title} ({rule.severity.upper()}):\n"
                explanation += f"   - Why it's a problem: {rule.description}\n"
                explanation += f"   - How to fix: {generate_fix_suggestion(code, rule, language)}\n"
                explanation += f"   - Code causing issue: {matched_text[:100]}{'...' if len(matched_text) > 100 else ''}\n\n"
            
            explanation += ("These issues could lead to security breaches, data leaks, or system compromise. "
                           "Address them before deploying to production.")
        else:
            explanation = ("No specific security vulnerabilities were detected in this code based on the current rule set. "
                          "However, security is a continuous process, and you should consider the following best practices:\n"
                          "- Regularly update dependencies\n"
                          "- Follow principle of least privilege\n"
                          "- Implement defense in depth\n"
                          "- Log security events appropriately\n"
                          "- Apply security patches promptly")
        
        return explanation

async def security_rule_details(db, arguments: dict):
    """Get detailed information about a specific security rule"""
    from models.rule import LocalRule

    rule_id = arguments.get("rule_id", "")
    include_examples = arguments.get("include_examples", False)

    # Find the rule by ID
    rule = db.query(LocalRule).filter(LocalRule.rule_id == rule_id).first()

    if not rule:
        return [TextContent(
            type="text",
            text=f"Rule with ID '{rule_id}' not found in the database."
        )]

    # Format rule details
    details = f"Rule Details for {rule.rule_id}:\n\n"
    details += f"Title: {rule.title}\n"
    details += f"Severity: {rule.severity.upper()}\n"
    details += f"Type: {rule.rule_type}\n"
    details += f"Source: {rule.source}\n\n"
    
    details += f"Description:\n{rule.description}\n\n"
    
    if rule.cve_refs:
        details += f"CVE References: {', '.join(rule.cve_refs)}\n"
    if rule.cwe_refs:
        details += f"CWE References: {', '.join(rule.cwe_refs)}\n"
    
    details += f"Enforcement Level: {rule.enforcement.get('level', 'N/A')}\n"
    details += f"Enforcement Message: {rule.enforcement.get('message', 'N/A')}\n"
    
    if include_examples:
        details += f"\nRequired Actions:\n"
        for action in rule.enforcement.get('required_actions', []):
            details += f"  - {action}\n"
        
        if rule.pattern:
            details += f"\nPattern Information:\n"
            details += f"  Type: {rule.pattern.get('type', 'N/A')}\n"
            details += f"  Language: {rule.pattern.get('language', 'N/A')}\n"
            details += f"  Value: {rule.pattern.get('value', 'N/A')}\n"
        
        if rule.applies_to:
            details += f"\nApplies To:\n"
            if rule.applies_to.get('languages'):
                details += f"  Languages: {', '.join(rule.applies_to['languages'])}\n"
            if rule.applies_to.get('frameworks'):
                details += f"  Frameworks: {', '.join(rule.applies_to['frameworks'])}\n"
            if rule.applies_to.get('contexts'):
                details += f"  Contexts: {', '.join(rule.applies_to['contexts'])}\n"
        
        if rule.external_refs:
            details += f"\nExternal References:\n"
            for ref in rule.external_refs:
                details += f"  - {ref}\n"
    
    return [TextContent(
        type="text",
        text=details
    )]

def get_compliance_status(db, arguments: dict):
    """Get project compliance status"""
    from models.rule import LocalRule
    from models.subscription import LocalSubscription
    from services.infra_detector import InfrastructureDetector
    
    project_path = arguments.get("project_path", ".")
    
    # Get subscription
    subscription = db.query(LocalSubscription).first()
    
    # Get rules count
    rules_count = db.query(LocalRule).count()
    
    # Detect infrastructure
    detector = InfrastructureDetector()
    stack = detector.detect(project_path)
    
    return [TextContent(
        type="text",
        text=f"""Subscription: {subscription.user_id if subscription else 'None'}
Rules loaded: {rules_count}
Detected stack: {stack}"""
    )]

def acknowledge_fix(db, arguments: dict):
    """Acknowledge a fix"""
    violation_id = arguments.get("violation_id")
    fix_description = arguments.get("fix_description")
    
    return [TextContent(
        type="text",
        text=f"Fix acknowledged for {violation_id}\nFix: {fix_description}"
    )]

def get_infrastructure_profile(db, arguments: dict):
    """Detect project infrastructure"""
    from services.infra_detector import InfrastructureDetector
    
    project_path = arguments.get("project_path", ".")
    
    detector = InfrastructureDetector()
    stack = detector.detect(project_path)
    
    return [TextContent(
        type="text",
        text=str(stack)
    )]

def sync_rules(db, arguments: dict):
    """Sync rules from backend"""
    from services.rule_sync import RuleSync
    from services.infra_detector import InfrastructureDetector
    
    rule_sync = RuleSync(db)
    
    # Get current stack for filtering
    detector = InfrastructureDetector()
    stack = detector.detect(".")
    
    result = rule_sync.sync_rules(stack)
    
    return [TextContent(
        type="text",
        text=str(result)
    )]

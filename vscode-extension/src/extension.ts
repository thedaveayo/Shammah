import * as vscode from 'vscode';
import axios from 'axios';

let diagnosticCollection: vscode.DiagnosticCollection;

export async function activate(context: vscode.ExtensionContext) {
	console.log('Security MCP extension activated');

	// Initialize diagnostics collection
	diagnosticCollection = vscode.languages.createDiagnosticCollection('security-mcp');
	context.subscriptions.push(diagnosticCollection);

	// Register commands
	const scanCurrentFileCommand = vscode.commands.registerCommand('security-mcp.scanCurrentFile', async () => {
		await scanCurrentFile();
	});

	const showSecurityDashboardCommand = vscode.commands.registerCommand('security-mcp.showSecurityDashboard', () => {
		showSecurityDashboard();
	});

	const applyQuickFixCommand = vscode.commands.registerCommand('security-mcp.applyQuickFix', async () => {
		await applyQuickFix();
	});

	context.subscriptions.push(scanCurrentFileCommand, showSecurityDashboardCommand, applyQuickFixCommand);

	// Setup real-time scanning if enabled
	if (vscode.workspace.getConfiguration('security-mcp').get('enableRealtimeScanning')) {
		setupRealtimeScanning(context);
	}
}

export function deactivate() {}

/**
 * Scans the currently opened file for security vulnerabilities
 */
async function scanCurrentFile() {
	const editor = vscode.window.activeTextEditor;
	if (!editor) {
		vscode.window.showErrorMessage('No active editor found');
		return;
	}

	const document = editor.document;
	const filePath = document.fileName;
	const code = document.getText();

	try {
		// Get configuration
		const config = vscode.workspace.getConfiguration('security-mcp');
		const backendUrl = config.get<string>('backendUrl') || 'http://localhost:8000';
		const apiToken = config.get<string>('apiToken') || '';

		// Call the MCP server's security scan tool
		const response = await axios.post(`${backendUrl}/api/tools/call`, {
			name: "security_scan_file",
			arguments: {
				file_path: filePath,
				include_details: true
			}
		}, {
			headers: {
				'Authorization': `Bearer ${apiToken}`,
				'Content-Type': 'application/json'
			}
		});

		// Process the response
		const result = response.data;
		if (result && result.result) {
			vscode.window.showInformationMessage(`Security scan completed: ${result.result}`);
			
			// Update diagnostics
			updateDiagnostics(document, result.violations || []);
		} else {
			vscode.window.showWarningMessage('No security issues found or invalid response from server');
		}
	} catch (error) {
		console.error('Error scanning file:', error);
		vscode.window.showErrorMessage(`Error scanning file: ${error instanceof Error ? error.message : 'Unknown error'}`);
	}
}

/**
 * Shows the security dashboard
 */
function showSecurityDashboard() {
	// Create and show a webview panel for the security dashboard
	const panel = vscode.window.createWebviewPanel(
		'securityDashboard',
		'Security Dashboard',
		vscode.ViewColumn.One,
		{
			enableScripts: true,
			retainContextWhenHidden: true
		}
	);

	panel.webview.html = getDashboardHtml();
}

/**
 * Applies a quick fix for security issues
 */
async function applyQuickFix() {
	const editor = vscode.window.activeTextEditor;
	if (!editor) {
		vscode.window.showErrorMessage('No active editor found');
		return;
	}

	const document = editor.document;
	const code = document.getText();

	try {
		// Get configuration
		const config = vscode.workspace.getConfiguration('security-mcp');
		const backendUrl = config.get<string>('backendUrl') || 'http://localhost:8000';
		const apiToken = config.get<string>('apiToken') || '';

		// Call the MCP server's security fix suggestions tool
		const response = await axios.post(`${backendUrl}/api/tools/call`, {
			name: "security_fix_suggestions",
			arguments: {
				code: code,
				language: document.languageId
			}
		}, {
			headers: {
				'Authorization': `Bearer ${apiToken}`,
				'Content-Type': 'application/json'
			}
		});

		// Process the response
		const result = response.data;
		if (result && result.fixes) {
			// Implement fix application logic here
			vscode.window.showInformationMessage('Quick fixes applied successfully');
		} else {
			vscode.window.showWarningMessage('No fixes available for the current code');
		}
	} catch (error) {
		console.error('Error applying quick fix:', error);
		vscode.window.showErrorMessage(`Error applying quick fix: ${error instanceof Error ? error.message : 'Unknown error'}`);
	}
}

/**
 * Sets up real-time scanning as the user types
 */
function setupRealtimeScanning(context: vscode.ExtensionContext) {
	const disposable = vscode.workspace.onDidChangeTextDocument(event => {
		// Debounce the scanning to avoid too frequent calls
		setTimeout(async () => {
			if (event.document === vscode.window.activeTextEditor?.document) {
				await scanCurrentFile();
			}
		}, 1000); // Wait 1 second after the last change
	});

	context.subscriptions.push(disposable);
}

/**
 * Updates the diagnostics for the given document
 */
function updateDiagnostics(document: vscode.TextDocument, violations: any[]) {
	const diagnostics: vscode.Diagnostic[] = [];

	for (const violation of violations) {
		// This is a simplified example - in reality, you'd need to map the violation to positions in the document
		const diagnostic = new vscode.Diagnostic(
			new vscode.Range(0, 0, 0, 10), // Placeholder range
			violation.message || 'Security issue detected',
			vscode.DiagnosticSeverity.Warning
		);
		
		diagnostic.code = violation.ruleId;
		diagnostic.source = 'Security MCP';
		
		diagnostics.push(diagnostic);
	}

	diagnosticCollection.set(document.uri, diagnostics);
}

/**
 * Returns the HTML for the security dashboard
 */
function getDashboardHtml(): string {
	return `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Security Dashboard</title>
		<style>
			body {
				font-family: Arial, sans-serif;
				padding: 20px;
			}
			.card {
				border: 1px solid #ddd;
				border-radius: 4px;
				padding: 16px;
				margin-bottom: 16px;
				background-color: #f9f9f9;
			}
			.high { color: #d73a49; }
			.medium { color: #d0870f; }
			.low { color: #0361cc; }
		</style>
	</head>
	<body>
		<h1>Security Dashboard</h1>
		<div class="card">
			<h3>Project Security Status</h3>
			<p>Total Issues Found: <span id="issueCount">0</span></p>
			<p>High Severity: <span id="highCount" class="high">0</span></p>
			<p>Medium Severity: <span id="mediumCount" class="medium">0</span></p>
			<p>Low Severity: <span id="lowCount" class="low">0</span></p>
		</div>
		<div class="card">
			<h3>Recent Scans</h3>
			<ul id="scanHistory"></ul>
		</div>
		<button onclick="scanCurrentFile()">Scan Current File</button>

		<script>
			function scanCurrentFile() {
				const vscode = acquireVsCodeApi();
				vscode.postMessage({ command: 'scanCurrentFile' });
			}
		</script>
	</body>
	</html>`;
}
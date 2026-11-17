import * as vscode from 'vscode';
import axios from 'axios';

/**
 * Shammah for VS Code.
 *
 * Talks to the local Shammah bridge (`python main.py --bridge` in mcp-server/),
 * which runs the same checks coding agents get through MCP.
 */

interface Violation {
	rule_id: string;
	title: string;
	severity: 'critical' | 'high' | 'medium' | 'low';
	message: string;
	required_actions: string[];
	references: string[];
	line: number;
	column: number;
	end_line: number;
	end_column: number;
}

interface ToolResponse {
	result: string;
	violations?: Violation[];
	counts?: Record<string, number>;
	blocked?: boolean;
	error?: string;
	[key: string]: unknown;
}

let diagnosticCollection: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let warnedUnreachable = false;
const pendingScans = new Map<string, NodeJS.Timeout>();

export function activate(context: vscode.ExtensionContext) {
	diagnosticCollection = vscode.languages.createDiagnosticCollection('shammah');
	output = vscode.window.createOutputChannel('Shammah');
	context.subscriptions.push(diagnosticCollection, output);

	context.subscriptions.push(
		vscode.commands.registerCommand('security-mcp.scanCurrentFile', () => scanActiveEditor(true)),
		vscode.commands.registerCommand('security-mcp.showSecurityDashboard', () => showSecurityDashboard()),
		vscode.commands.registerCommand('security-mcp.applyQuickFix', () => showFixSuggestions()),
		vscode.workspace.onDidChangeTextDocument(event => scheduleScan(event.document)),
		vscode.workspace.onDidOpenTextDocument(document => scheduleScan(document)),
		vscode.workspace.onDidSaveTextDocument(document => scheduleScan(document)),
		vscode.workspace.onDidCloseTextDocument(document => diagnosticCollection.delete(document.uri)),
	);

	if (vscode.window.activeTextEditor) {
		scheduleScan(vscode.window.activeTextEditor.document);
	}
}

export function deactivate() {
	for (const timer of pendingScans.values()) {
		clearTimeout(timer);
	}
	pendingScans.clear();
}

function config() {
	return vscode.workspace.getConfiguration('security-mcp');
}

function serverUrl(): string {
	return (config().get<string>('serverUrl') || 'http://127.0.0.1:8765').replace(/\/+$/, '');
}

async function callTool(name: string, args: Record<string, unknown>): Promise<ToolResponse> {
	try {
		const response = await axios.post<ToolResponse>(`${serverUrl()}/api/tools/call`, { name, arguments: args }, {
			headers: { 'Content-Type': 'application/json' },
			timeout: 30000,
		});
		warnedUnreachable = false;
		return response.data;
	} catch (error) {
		if (axios.isAxiosError(error) && error.response?.data?.error) {
			throw new Error(error.response.data.error);
		}
		if (!warnedUnreachable) {
			warnedUnreachable = true;
			vscode.window.showWarningMessage(
				`Shammah: can't reach ${serverUrl()}. Start it with "python main.py --bridge" in the mcp-server folder.`);
		}
		throw error;
	}
}

function scheduleScan(document: vscode.TextDocument) {
	if (!config().get<boolean>('enableRealtimeScanning', true) || document.uri.scheme !== 'file') {
		return;
	}
	const key = document.uri.toString();
	const existing = pendingScans.get(key);
	if (existing) {
		clearTimeout(existing);
	}
	pendingScans.set(key, setTimeout(() => {
		pendingScans.delete(key);
		scanDocument(document).catch(() => undefined);
	}, 1000));
}

async function scanActiveEditor(announce: boolean) {
	const editor = vscode.window.activeTextEditor;
	if (!editor) {
		vscode.window.showErrorMessage('No active editor found');
		return;
	}
	try {
		const result = await scanDocument(editor.document);
		if (announce) {
			const count = result.violations?.length ?? 0;
			vscode.window.showInformationMessage(count === 0
				? 'Shammah: no security issues found.'
				: `Shammah: ${count} security issue(s) found. See the Problems panel.`);
		}
	} catch (error) {
		vscode.window.showErrorMessage(`Shammah: scan failed: ${error instanceof Error ? error.message : String(error)}`);
	}
}

async function scanDocument(document: vscode.TextDocument): Promise<ToolResponse> {
	const result = await callTool('enforce_security', {
		code: document.getText(),
		language: document.languageId,
	});
	diagnosticCollection.set(document.uri, toDiagnostics(document, result.violations ?? []));
	return result;
}

function toDiagnostics(document: vscode.TextDocument, violations: Violation[]): vscode.Diagnostic[] {
	return violations.map(v => {
		const start = document.validatePosition(new vscode.Position(Math.max(v.line - 1, 0), Math.max(v.column - 1, 0)));
		const end = document.validatePosition(new vscode.Position(Math.max(v.end_line - 1, 0), Math.max(v.end_column - 1, 0)));
		const range = start.isEqual(end) ? document.lineAt(start.line).range : new vscode.Range(start, end);
		const fix = v.required_actions?.length ? ` Fix: ${v.required_actions.join('; ')}` : '';
		const diagnostic = new vscode.Diagnostic(range, `${v.title}: ${v.message}${fix}`, severityOf(v.severity));
		diagnostic.code = v.rule_id;
		diagnostic.source = 'Shammah';
		return diagnostic;
	});
}

function severityOf(severity: Violation['severity']): vscode.DiagnosticSeverity {
	switch (severity) {
		case 'critical':
		case 'high':
			return vscode.DiagnosticSeverity.Error;
		case 'medium':
			return vscode.DiagnosticSeverity.Warning;
		default:
			return vscode.DiagnosticSeverity.Information;
	}
}

async function showFixSuggestions() {
	const editor = vscode.window.activeTextEditor;
	if (!editor) {
		vscode.window.showErrorMessage('No active editor found');
		return;
	}
	try {
		const result = await callTool('security_fix_suggestions', {
			code: editor.document.getText(),
			language: editor.document.languageId,
		});
		output.clear();
		output.appendLine(result.result);
		output.show(true);
	} catch (error) {
		vscode.window.showErrorMessage(`Shammah: ${error instanceof Error ? error.message : String(error)}`);
	}
}

async function showSecurityDashboard() {
	const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	let status = 'Open a folder to see its status.';
	try {
		status = (await callTool('get_compliance_status', { project_path: folder ?? '.' })).result;
	} catch (error) {
		status = `Could not reach the Shammah bridge at ${serverUrl()}.`;
	}

	const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
	diagnosticCollection.forEach((_uri, diagnostics) => {
		for (const d of diagnostics) {
			if (d.severity === vscode.DiagnosticSeverity.Error) { counts.high++; }
			else if (d.severity === vscode.DiagnosticSeverity.Warning) { counts.medium++; }
			else { counts.low++; }
		}
	});

	const panel = vscode.window.createWebviewPanel('shammahDashboard', 'Shammah', vscode.ViewColumn.One, {
		enableScripts: false,
	});
	panel.webview.html = dashboardHtml(status, counts);
}

function escapeHtml(text: string): string {
	return text.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

function dashboardHtml(status: string, counts: Record<string, number>): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
	<title>Shammah</title>
	<style>
		body { font-family: var(--vscode-font-family); padding: 16px; }
		.card { border: 1px solid var(--vscode-panel-border); border-radius: 4px; padding: 12px 16px; margin-bottom: 16px; }
		pre { white-space: pre-wrap; }
	</style>
</head>
<body>
	<h1>Shammah</h1>
	<div class="card">
		<h3>Open files</h3>
		<p>Errors (critical/high): ${counts.high}</p>
		<p>Warnings (medium): ${counts.medium}</p>
		<p>Info (low): ${counts.low}</p>
	</div>
	<div class="card">
		<h3>Rules and project</h3>
		<pre>${escapeHtml(status)}</pre>
	</div>
</body>
</html>`;
}

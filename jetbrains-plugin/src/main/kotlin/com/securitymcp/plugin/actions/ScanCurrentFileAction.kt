package com.securitymcp.plugin.actions

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.ui.Messages
import com.securitymcp.plugin.services.SecurityMCPClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class ScanCurrentFileAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val fileEditorManager = FileEditorManager.getInstance(project)
        val currentFile = fileEditorManager.selectedFiles.firstOrNull()

        if (currentFile != null) {
            val filePath = currentFile.path

            // Use coroutines to perform the API call asynchronously
            CoroutineScope(Dispatchers.IO).launch {
                val client = SecurityMCPClient.getInstance(project)
                val result = client.scanFile(filePath, true)

                // Back to UI thread to show the message
                kotlinx.coroutines.withContext(Dispatchers.Main) {
                    Messages.showMessageDialog(
                        project,
                        "Security scan result: $result",
                        "Security MCP Scan Result",
                        Messages.getInformationIcon()
                    )
                }
            }
        } else {
            Messages.showMessageDialog(
                project,
                "No file is currently open in the editor",
                "Security MCP",
                Messages.getWarningIcon()
            )
        }
    }
}
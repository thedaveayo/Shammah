package com.securitymcp.plugin.ui

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory
import javax.swing.*

class SecurityDashboardToolWindowFactory : ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val myToolWindow = SecurityDashboardToolWindow(project)
        val contentFactory = ContentFactory.getInstance()
        val content = contentFactory.createContent(myToolWindow.getContent(), "", false)
        toolWindow.contentManager.addContent(content)
    }
}

class SecurityDashboardToolWindow(private val project: Project) {
    fun getContent(): JComponent {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)

        val titleLabel = JLabel("Security MCP Dashboard")
        titleLabel.alignmentX = java.awt.Component.LEFT_ALIGNMENT
        panel.add(titleLabel)
        panel.add(Box.createVerticalStrut(10)) // spacer

        val issueCountLabel = JLabel("Total Issues Found: 0")
        issueCountLabel.alignmentX = java.awt.Component.LEFT_ALIGNMENT
        panel.add(issueCountLabel)
        panel.add(Box.createVerticalStrut(5))

        val highCountLabel = JLabel("High Severity: 0")
        highCountLabel.alignmentX = java.awt.Component.LEFT_ALIGNMENT
        panel.add(highCountLabel)
        panel.add(Box.createVerticalStrut(5))

        val mediumCountLabel = JLabel("Medium Severity: 0")
        mediumCountLabel.alignmentX = java.awt.Component.LEFT_ALIGNMENT
        panel.add(mediumCountLabel)
        panel.add(Box.createVerticalStrut(5))

        val lowCountLabel = JLabel("Low Severity: 0")
        lowCountLabel.alignmentX = java.awt.Component.LEFT_ALIGNMENT
        panel.add(lowCountLabel)
        panel.add(Box.createVerticalStrut(20))

        val scanButton = JButton("Scan Current File")
        scanButton.alignmentX = java.awt.Component.LEFT_ALIGNMENT
        scanButton.addActionListener {
            // TODO: Implement scan functionality
        }
        panel.add(scanButton)

        return panel
    }
}
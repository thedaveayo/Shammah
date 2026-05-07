package com.securitymcp.plugin

import com.intellij.openapi.project.Project
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.securitymcp.plugin.services.SecurityMCPClient

@Service(Service.Level.PROJECT)
class SecurityMCPProjectService(val project: Project) {

    val client: SecurityMCPClient = SecurityMCPClient.getInstance(project)

    companion object {
        fun getInstance(project: Project): SecurityMCPProjectService {
            return project.service<SecurityMCPProjectService>()
        }
    }
}
package com.securitymcp.plugin.services

import com.intellij.openapi.project.Project
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import okhttp3.*
import java.io.IOException

@Service(Service.Level.PROJECT)
class SecurityMCPClient(private val project: Project) {

    private val httpClient = OkHttpClient()
    private val gson = com.google.gson.Gson()

    companion object {
        fun getInstance(project: Project): SecurityMCPClient {
            return project.service<SecurityMCPClient>()
        }
    }

    suspend fun scanFile(filePath: String, includeDetails: Boolean = false): String {
        val requestBody = mapOf(
            "name" to "security_scan_file",
            "arguments" to mapOf(
                "file_path" to filePath,
                "include_details" to includeDetails
            )
        )

        val jsonBody = gson.toJson(requestBody)
        val body = RequestBody.create(MediaType.get("application/json"), jsonBody)

        val request = Request.Builder()
            .url(getBackendUrl() + "/api/tools/call")
            .post(body)
            .addHeader("Authorization", "Bearer ${getApiToken()}")
            .build()

        return try {
            val response = httpClient.newCall(request).execute()
            response.body?.string() ?: "Error: Empty response body"
        } catch (e: IOException) {
            "Error: ${e.message}"
        }
    }

    suspend fun getFixSuggestions(code: String, language: String): String {
        val requestBody = mapOf(
            "name" to "security_fix_suggestions",
            "arguments" to mapOf(
                "code" to code,
                "language" to language
            )
        )

        val jsonBody = gson.toJson(requestBody)
        val body = RequestBody.create(MediaType.get("application/json"), jsonBody)

        val request = Request.Builder()
            .url(getBackendUrl() + "/api/tools/call")
            .post(body)
            .addHeader("Authorization", "Bearer ${getApiToken()}")
            .build()

        return try {
            val response = httpClient.newCall(request).execute()
            response.body?.string() ?: "Error: Empty response body"
        } catch (e: IOException) {
            "Error: ${e.message}"
        }
    }

    private fun getBackendUrl(): String {
        // Get from project settings, fallback to default
        return "http://localhost:8000" // TODO: Get from settings
    }

    private fun getApiToken(): String {
        // Get from project settings
        return "" // TODO: Get from settings
    }
}
package com.keyvora.app.sync

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.net.URLEncoder
import java.security.SecureRandom

/**
 * [RemoteStore] over Google Drive API v3 in the hidden `appDataFolder` (scope `drive.appdata`, ADR-008).
 * Only the encrypted container is ever sent. Tokens come from [AccessTokenProvider] and are never logged.
 *
 * If several `keyvora-vault.json` files exist (two first uploads raced), the oldest (`orderBy=createdTime`) is used
 * by every client, so they converge; the other file's data is still in its creator's local vault and gets merged
 * into the canonical file on that device's next sync.
 */
class GoogleDriveRemoteStore(
    private val http: HttpTransport,
    private val tokens: AccessTokenProvider,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) : RemoteStore {

    override suspend fun getMetadata(): RemoteMeta? {
        val q = "name = '$FILE_NAME' and trashed = false"
        val url = "$API/files?spaces=appDataFolder&q=${enc(q)}&orderBy=createdTime&pageSize=10" +
            "&fields=${enc("files($FIELDS)")}"
        val files = parse(send("GET", url)).optJSONArray("files") ?: return null
        if (files.length() == 0) return null
        return meta(files.getJSONObject(0))
    }

    override suspend fun download(fileId: String): RemoteDownload {
        val id = seg(fileId)
        // Read head → content → head; equal heads guarantee the content belongs to that revision.
        repeat(3) {
            val before = getFile(id)
            val content = send("GET", "$API/files/$id?alt=media").text()
            val after = getFile(id)
            if (before.headRevisionId == after.headRevisionId) return RemoteDownload(content, after.headRevisionId)
        }
        throw RemoteException(RemoteErrorCode.NETWORK) // kept changing; retried with backoff
    }

    override suspend fun create(content: String): RemoteMeta {
        val boundary = boundaryFor(content)
        val metadata = JSONObject()
            .put("name", FILE_NAME)
            .put("parents", org.json.JSONArray().put("appDataFolder"))
            .put("mimeType", MIME_JSON)
            .toString()
        val body = buildString {
            append("--").append(boundary).append("\r\n")
            append("Content-Type: application/json; charset=UTF-8\r\n\r\n")
            append(metadata).append("\r\n")
            append("--").append(boundary).append("\r\n")
            append("Content-Type: ").append(MIME_JSON).append("\r\n\r\n")
            append(content).append("\r\n")
            append("--").append(boundary).append("--\r\n")
        }.toByteArray(Charsets.UTF_8)
        val url = "$UPLOAD/files?uploadType=multipart&fields=${enc(FIELDS)}"
        return meta(parse(send("POST", url, "multipart/related; boundary=$boundary", body)))
    }

    override suspend fun update(fileId: String, content: String): RemoteMeta {
        val url = "$UPLOAD/files/${seg(fileId)}?uploadType=media&fields=${enc(FIELDS)}"
        return meta(parse(send("PATCH", url, MIME_JSON, content.toByteArray(Charsets.UTF_8))))
    }

    override suspend fun listRevisions(fileId: String): List<RevisionInfo> {
        val id = seg(fileId)
        val out = mutableListOf<RevisionInfo>()
        var pageToken: String? = null
        do {
            val url = "$API/files/$id/revisions?pageSize=200&fields=${enc("nextPageToken,revisions(id,modifiedTime,size)")}" +
                (pageToken?.let { "&pageToken=${enc(it)}" } ?: "")
            val json = parse(send("GET", url))
            val arr = json.optJSONArray("revisions")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val r = arr.getJSONObject(i)
                    out += RevisionInfo(r.getString("id"), r.optStringOrNull("modifiedTime"), r.optStringOrNull("size")?.toLongOrNull())
                }
            }
            pageToken = json.optStringOrNull("nextPageToken")
        } while (pageToken != null && out.size < MAX_REVISIONS)
        return out
    }

    override suspend fun downloadRevision(fileId: String, revisionId: String): String =
        send("GET", "$API/files/${seg(fileId)}/revisions/${seg(revisionId)}?alt=media").text()

    private suspend fun getFile(id: String): RemoteMeta = meta(parse(send("GET", "$API/files/$id?fields=${enc(FIELDS)}")))

    private suspend fun send(method: String, url: String, contentType: String? = null, body: ByteArray? = null): HttpResponse =
        withContext(io) {
            var token = tokens.accessToken()
            var resp = exec(method, url, token, contentType, body)
            if (resp.status == 401) {
                tokens.invalidate(token)
                token = tokens.accessToken()
                resp = exec(method, url, token, contentType, body)
            }
            if (resp.status !in 200..299) throw mapError(resp)
            resp
        }

    private fun exec(method: String, url: String, token: String, contentType: String?, body: ByteArray?): HttpResponse {
        val headers = buildMap {
            put("Authorization", "Bearer $token")
            put("Accept", "application/json")
            if (contentType != null) put("Content-Type", contentType)
        }
        return try {
            http.execute(HttpRequest(method, url, headers, body))
        } catch (e: IOException) {
            throw RemoteException(RemoteErrorCode.NETWORK, cause = e)
        }
    }

    private fun parse(resp: HttpResponse): JSONObject = try {
        JSONObject(resp.text())
    } catch (e: JSONException) {
        throw RemoteException(RemoteErrorCode.REMOTE_ERROR, resp.status, cause = e)
    }

    private fun meta(o: JSONObject): RemoteMeta {
        val id = o.optStringOrNull("id") ?: throw RemoteException(RemoteErrorCode.REMOTE_ERROR)
        val head = o.optStringOrNull("headRevisionId") ?: throw RemoteException(RemoteErrorCode.REMOTE_ERROR)
        return RemoteMeta(id, head, o.optStringOrNull("modifiedTime"), o.optStringOrNull("size")?.toLongOrNull())
    }

    private fun boundaryFor(content: String): String {
        val rnd = SecureRandom()
        while (true) {
            val b = "keyvora_" + ByteArray(16).also(rnd::nextBytes).joinToString("") { "%02x".format(it) }
            if (!content.contains(b)) return b
        }
    }

    companion object {
        const val FILE_NAME = "keyvora-vault.json"
        const val API = "https://www.googleapis.com/drive/v3"
        const val UPLOAD = "https://www.googleapis.com/upload/drive/v3"
        const val FIELDS = "id,headRevisionId,modifiedTime,size"
        const val MIME_JSON = "application/json"
        const val SCOPE_DRIVE_APPDATA = "https://www.googleapis.com/auth/drive.appdata"
        private const val MAX_REVISIONS = 2_000
        private val SAFE_ID = Regex("^[A-Za-z0-9_\\-]{1,256}$")

        /** Maps an HTTP error to the transport codes of CONTRACTS §6. */
        fun mapError(resp: HttpResponse): RemoteException {
            val status = resp.status
            val retryAfter = resp.header("Retry-After")?.trim()?.toLongOrNull()?.times(1000)
            val reason = errorReason(resp)
            val code = when {
                status == 401 -> RemoteErrorCode.AUTH_REQUIRED
                status == 429 -> RemoteErrorCode.RATE_LIMITED
                status == 403 && reason in RATE_REASONS -> RemoteErrorCode.RATE_LIMITED
                status == 403 && reason in AUTH_REASONS -> RemoteErrorCode.AUTH_REQUIRED
                status == 408 || status in 500..599 -> RemoteErrorCode.NETWORK
                else -> RemoteErrorCode.REMOTE_ERROR
            }
            return RemoteException(code, status, retryAfter)
        }

        private val RATE_REASONS = setOf("rateLimitExceeded", "userRateLimitExceeded", "dailyLimitExceeded")
        private val AUTH_REASONS = setOf("insufficientPermissions", "insufficientScopes", "authError", "ACCESS_TOKEN_SCOPE_INSUFFICIENT")

        private fun errorReason(resp: HttpResponse): String? = try {
            val err = JSONObject(resp.text()).optJSONObject("error")
            err?.optJSONArray("errors")?.optJSONObject(0)?.optStringOrNull("reason")
                ?: err?.optJSONArray("details")?.optJSONObject(0)?.optStringOrNull("reason")
                ?: err?.optStringOrNull("status")
        } catch (_: JSONException) {
            null
        }

        private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8").replace("+", "%20")

        /** Validates ids used as URL path segments (defense against path injection from server data). */
        private fun seg(id: String): String {
            if (!SAFE_ID.matches(id)) throw RemoteException(RemoteErrorCode.REMOTE_ERROR)
            return id
        }

        private fun JSONObject.optStringOrNull(key: String): String? =
            if (has(key) && !isNull(key)) optString(key).takeIf { it.isNotEmpty() } else null
    }
}

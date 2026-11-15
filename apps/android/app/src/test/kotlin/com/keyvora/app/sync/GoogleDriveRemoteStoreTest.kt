package com.keyvora.app.sync

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.net.URLDecoder

class GoogleDriveRemoteStoreTest {
    private class FakeHttp : HttpTransport {
        val requests = mutableListOf<HttpRequest>()
        val responses = ArrayDeque<() -> HttpResponse>()

        fun respond(status: Int, body: String = "", headers: Map<String, List<String>> = emptyMap()) {
            responses.addLast { HttpResponse(status, headers, body.toByteArray()) }
        }

        fun throwIo() {
            responses.addLast { throw IOException("offline") }
        }

        override fun execute(request: HttpRequest): HttpResponse {
            requests += request
            return (responses.removeFirstOrNull() ?: error("unexpected request ${request.method} ${request.url}")).invoke()
        }
    }

    private class FakeTokens : AccessTokenProvider {
        var issued = 0
        val invalidated = mutableListOf<String>()
        override suspend fun accessToken() = "tok-${++issued}"
        override suspend fun invalidate(token: String) {
            invalidated += token
        }
    }

    private val http = FakeHttp()
    private val tokens = FakeTokens()
    private val store = GoogleDriveRemoteStore(http, tokens, Dispatchers.Unconfined)

    private fun decoded(url: String) = URLDecoder.decode(url, "UTF-8")

    @Test
    fun getMetadataQueriesAppDataFolder() = runTest {
        http.respond(200, """{"files":[{"id":"F1","headRevisionId":"H1","modifiedTime":"2026-01-01T00:00:00Z","size":"123"}]}""")
        val meta = store.getMetadata()
        assertEquals(RemoteMeta("F1", "H1", "2026-01-01T00:00:00Z", 123), meta)
        val req = http.requests.single()
        assertEquals("GET", req.method)
        val url = decoded(req.url)
        assertTrue(url.startsWith("https://www.googleapis.com/drive/v3/files?"))
        assertTrue(url.contains("spaces=appDataFolder"))
        assertTrue(url.contains("q=name = 'keyvora-vault.json' and trashed = false"))
        assertTrue(url.contains("fields=files(id,headRevisionId,modifiedTime,size)"))
        assertTrue(url.contains("orderBy=createdTime"))
        assertEquals("Bearer tok-1", req.headers["Authorization"])
    }

    @Test
    fun getMetadataReturnsNullWhenNoFile() = runTest {
        http.respond(200, """{"files":[]}""")
        assertNull(store.getMetadata())
    }

    @Test
    fun createUsesMultipartWithAppDataParent() = runTest {
        http.respond(200, """{"id":"F1","headRevisionId":"H1"}""")
        val meta = store.create("""{"format":"keyvora.vault"}""")
        assertEquals("F1", meta.fileId)
        val req = http.requests.single()
        assertEquals("POST", req.method)
        assertTrue(req.url.startsWith("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"))
        assertTrue(decoded(req.url).contains("fields=id,headRevisionId,modifiedTime,size"))
        val ct = req.headers["Content-Type"]!!
        assertTrue(ct.startsWith("multipart/related; boundary="))
        val boundary = ct.substringAfter("boundary=")
        val body = String(req.body!!)
        assertTrue(body.startsWith("--$boundary\r\n"))
        assertTrue(body.contains("\"parents\":[\"appDataFolder\"]"))
        assertTrue(body.contains("\"name\":\"keyvora-vault.json\""))
        assertTrue(body.contains("{\"format\":\"keyvora.vault\"}"))
        assertTrue(body.endsWith("--$boundary--\r\n"))
    }

    @Test
    fun updateUsesPatchMediaUpload() = runTest {
        http.respond(200, """{"id":"F1","headRevisionId":"H2","size":"9"}""")
        val meta = store.update("F1", "CONTAINER")
        assertEquals("H2", meta.headRevisionId)
        val req = http.requests.single()
        assertEquals("PATCH", req.method)
        assertTrue(req.url.startsWith("https://www.googleapis.com/upload/drive/v3/files/F1?uploadType=media"))
        assertEquals("application/json", req.headers["Content-Type"])
        assertEquals("CONTAINER", String(req.body!!))
    }

    @Test
    fun downloadReturnsContentOfAStableHeadRevision() = runTest {
        http.respond(200, """{"id":"F1","headRevisionId":"H1"}""")
        http.respond(200, "OLD")
        http.respond(200, """{"id":"F1","headRevisionId":"H2"}""") // changed during download → retry
        http.respond(200, """{"id":"F1","headRevisionId":"H2"}""")
        http.respond(200, "NEW")
        http.respond(200, """{"id":"F1","headRevisionId":"H2"}""")
        val d = store.download("F1")
        assertEquals("NEW", d.content)
        assertEquals("H2", d.headRevisionId)
        assertTrue(http.requests[1].url.endsWith("/files/F1?alt=media"))
    }

    @Test
    fun listRevisionsFollowsPagination() = runTest {
        http.respond(200, """{"revisions":[{"id":"R1","size":"10"},{"id":"R2"}],"nextPageToken":"P2"}""")
        http.respond(200, """{"revisions":[{"id":"R3","modifiedTime":"t3"}]}""")
        val revs = store.listRevisions("F1")
        assertEquals(listOf("R1", "R2", "R3"), revs.map { it.id })
        assertEquals(10L, revs[0].size)
        assertTrue(http.requests[1].url.contains("pageToken=P2"))
        assertTrue(decoded(http.requests[0].url).contains("fields=nextPageToken,revisions(id,modifiedTime,size)"))
    }

    @Test
    fun downloadRevisionUsesAltMedia() = runTest {
        http.respond(200, "REV")
        assertEquals("REV", store.downloadRevision("F1", "R9"))
        assertTrue(http.requests.single().url.endsWith("/files/F1/revisions/R9?alt=media"))
    }

    @Test
    fun unauthorizedOnceRefreshesTokenAndRetries() = runTest {
        http.respond(401)
        http.respond(200, """{"files":[]}""")
        assertNull(store.getMetadata())
        assertEquals(listOf("tok-1"), tokens.invalidated)
        assertEquals("Bearer tok-2", http.requests[1].headers["Authorization"])
    }

    @Test
    fun unauthorizedTwiceIsAuthRequired() = runTest {
        http.respond(401)
        http.respond(401)
        assertCode(RemoteErrorCode.AUTH_REQUIRED) { store.getMetadata() }
    }

    @Test
    fun errorMapping() = runTest {
        http.respond(429, "", mapOf("Retry-After" to listOf("7")))
        val e = assertCode(RemoteErrorCode.RATE_LIMITED) { store.getMetadata() }
        assertEquals(7_000L, e.retryAfterMs)

        http.respond(403, """{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}""")
        assertCode(RemoteErrorCode.RATE_LIMITED) { store.getMetadata() }

        http.respond(403, """{"error":{"errors":[{"reason":"insufficientPermissions"}]}}""")
        assertCode(RemoteErrorCode.AUTH_REQUIRED) { store.getMetadata() }

        http.respond(403, """{"error":{"errors":[{"reason":"storageQuotaExceeded"}]}}""")
        assertCode(RemoteErrorCode.REMOTE_ERROR) { store.getMetadata() }

        http.respond(503)
        assertCode(RemoteErrorCode.NETWORK) { store.getMetadata() }

        http.throwIo()
        assertCode(RemoteErrorCode.NETWORK) { store.getMetadata() }

        http.respond(404, """{"error":{"code":404}}""")
        val nf = assertCode(RemoteErrorCode.REMOTE_ERROR) { store.update("F1", "x") }
        assertEquals(404, nf.httpStatus)

        http.respond(200, "not json")
        assertCode(RemoteErrorCode.REMOTE_ERROR) { store.getMetadata() }
    }

    @Test
    fun unsafeIdsAreRejectedBeforeAnyRequest() = runTest {
        assertCode(RemoteErrorCode.REMOTE_ERROR) { store.downloadRevision("F1/../x", "R1") }
        assertCode(RemoteErrorCode.REMOTE_ERROR) { store.update("F1?alt=media", "x") }
        assertTrue(http.requests.isEmpty())
    }

    @Test
    fun requestToStringNeverShowsTokenOrBody() {
        val r = HttpRequest("PATCH", "https://x/y?uploadType=media", mapOf("Authorization" to "Bearer secret-token"), "BODY".toByteArray())
        assertFalse(r.toString().contains("secret-token"))
        assertFalse(r.toString().contains("BODY"))
    }

    private suspend fun assertCode(code: RemoteErrorCode, block: suspend () -> Unit): RemoteException {
        try {
            block()
        } catch (e: RemoteException) {
            assertEquals(code, e.code)
            return e
        }
        fail("expected $code")
        throw AssertionError()
    }
}

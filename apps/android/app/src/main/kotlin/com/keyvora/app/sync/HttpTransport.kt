package com.keyvora.app.sync

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

class HttpRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String> = emptyMap(),
    val body: ByteArray? = null,
) {
    // Headers contain the bearer token and the body the container: never print them.
    override fun toString() = "HttpRequest($method ${url.substringBefore('?')})"
}

class HttpResponse(val status: Int, val headers: Map<String, List<String>> = emptyMap(), val body: ByteArray = ByteArray(0)) {
    fun text(): String = body.toString(Charsets.UTF_8)
    fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()
    override fun toString() = "HttpResponse($status)"
}

/** Blocking HTTP layer (called on Dispatchers.IO). Throws IOException on transport failures. */
fun interface HttpTransport {
    @Throws(IOException::class)
    fun execute(request: HttpRequest): HttpResponse
}

/** Production transport over [HttpURLConnection] (HTTPS only, no caches, bounded response size). */
class HttpUrlConnectionTransport(
    private val connectTimeoutMs: Int = 15_000,
    private val readTimeoutMs: Int = 60_000,
    private val maxResponseBytes: Int = 80 * 1024 * 1024,
) : HttpTransport {
    override fun execute(request: HttpRequest): HttpResponse {
        require(request.url.startsWith("https://")) { "HTTPS required" }
        val conn = URL(request.url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = request.method // Android's HttpURLConnection supports PATCH.
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            conn.useCaches = false
            conn.instanceFollowRedirects = true
            request.headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            val body = request.body
            if (body != null) {
                conn.doOutput = true
                conn.setFixedLengthStreamingMode(body.size)
                conn.outputStream.use { it.write(body) }
            }
            val status = conn.responseCode
            val stream = if (status >= 400) conn.errorStream else conn.inputStream
            val bytes = stream?.use { readBounded(it) } ?: ByteArray(0)
            val headers = conn.headerFields.filterKeys { it != null }.mapKeys { it.key!! }
            return HttpResponse(status, headers, bytes)
        } finally {
            conn.disconnect()
        }
    }

    private fun readBounded(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        var total = 0
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > maxResponseBytes) throw IOException("response too large")
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }
}

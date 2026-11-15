package com.keyvora.app.sync

/** Metadata of the remote vault file (docs/CONTRACTS.md §6). */
data class RemoteMeta(
    val fileId: String,
    val headRevisionId: String,
    val modifiedTime: String? = null,
    val size: Long? = null,
)

data class RemoteDownload(val content: String, val headRevisionId: String) {
    override fun toString() = "RemoteDownload(headRevisionId=$headRevisionId, length=${content.length})"
}

data class RevisionInfo(val id: String, val modifiedTime: String? = null, val size: Long? = null)

/** Transport error codes shared with the extension (CONTRACTS §6). */
enum class RemoteErrorCode(val retryable: Boolean) {
    NETWORK(true),
    AUTH_REQUIRED(false),
    RATE_LIMITED(true),
    REMOTE_ERROR(false),
}

/** Never carries tokens, URLs with credentials or file contents. */
class RemoteException(
    val code: RemoteErrorCode,
    val httpStatus: Int? = null,
    val retryAfterMs: Long? = null,
    cause: Throwable? = null,
) : Exception(code.name + (httpStatus?.let { " ($it)" } ?: ""), cause)

/**
 * Remote storage of the encrypted container. Only ciphertext containers cross this interface.
 * All functions may throw [RemoteException].
 */
interface RemoteStore {
    /** Metadata of `keyvora-vault.json`, or null if it does not exist yet. */
    suspend fun getMetadata(): RemoteMeta?

    /** Content plus the head revision id that content corresponds to. */
    suspend fun download(fileId: String): RemoteDownload
    suspend fun create(content: String): RemoteMeta
    suspend fun update(fileId: String, content: String): RemoteMeta

    /** Chronological order (oldest first). */
    suspend fun listRevisions(fileId: String): List<RevisionInfo>
    suspend fun downloadRevision(fileId: String, revisionId: String): String
}

/** Supplies OAuth access tokens. Implementations never persist or log them. */
interface AccessTokenProvider {
    /** @throws RemoteException AUTH_REQUIRED when interactive consent is needed. */
    suspend fun accessToken(): String

    /** Called after a 401 so the next [accessToken] call returns a fresh token. */
    suspend fun invalidate(token: String)
}

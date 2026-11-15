package com.keyvora.app.sync

/**
 * TEST [RemoteStore] (CONTRACTS §6): one file with a full revision history, injectable failures and an
 * interleaving hook that lets another "client" write between our pre-check and our upload.
 */
class InMemoryRemoteStore : RemoteStore {
    class Rev(val id: String, val content: String)

    private var revCounter = 0
    var fileId: String? = null
        private set
    val revisions = mutableListOf<Rev>()
    val calls = mutableListOf<String>()

    /** Failures thrown (once each, FIFO) by the named operation before it takes effect. */
    val failures = mutableMapOf<String, ArrayDeque<RemoteException>>()

    /** Failures thrown by `update` AFTER the new revision was committed (response lost). */
    val failuresAfterCommit = ArrayDeque<RemoteException>()

    /** Runs inside `update`, before it is applied (simulates another client writing at that moment). */
    var beforeUpdate: (suspend () -> Unit)? = null

    val head: Rev? get() = revisions.lastOrNull()

    fun fail(op: String, e: RemoteException) {
        failures.getOrPut(op) { ArrayDeque() }.addLast(e)
    }

    private fun maybeFail(op: String) {
        calls += op
        failures[op]?.removeFirstOrNull()?.let { throw it }
    }

    private fun newRev(content: String): Rev = Rev("r${++revCounter}", content).also { revisions += it }

    private fun meta(): RemoteMeta = RemoteMeta(fileId!!, head!!.id, "t${revisions.size}", head!!.content.length.toLong())

    /** Another client writes directly (no merge): used to create remote changes and interleavings. */
    fun externalWrite(content: String) {
        if (fileId == null) fileId = "file-1"
        newRev(content)
    }

    /** Simulates a rollback: the head becomes the content of an older revision. */
    fun rollbackTo(revisionId: String) {
        newRev(revisions.first { it.id == revisionId }.content)
    }

    override suspend fun getMetadata(): RemoteMeta? {
        maybeFail("getMetadata")
        return if (fileId == null) null else meta()
    }

    override suspend fun download(fileId: String): RemoteDownload {
        maybeFail("download")
        if (fileId != this.fileId) throw RemoteException(RemoteErrorCode.REMOTE_ERROR, 404)
        return RemoteDownload(head!!.content, head!!.id)
    }

    override suspend fun create(content: String): RemoteMeta {
        maybeFail("create")
        fileId = "file-1"
        newRev(content)
        return meta()
    }

    override suspend fun update(fileId: String, content: String): RemoteMeta {
        maybeFail("update")
        beforeUpdate?.invoke()
        if (fileId != this.fileId) throw RemoteException(RemoteErrorCode.REMOTE_ERROR, 404)
        newRev(content)
        val m = meta()
        failuresAfterCommit.removeFirstOrNull()?.let { throw it }
        return m
    }

    override suspend fun listRevisions(fileId: String): List<RevisionInfo> {
        maybeFail("listRevisions")
        return revisions.map { RevisionInfo(it.id, null, it.content.length.toLong()) }
    }

    override suspend fun downloadRevision(fileId: String, revisionId: String): String {
        maybeFail("downloadRevision")
        return revisions.first { it.id == revisionId }.content
    }
}

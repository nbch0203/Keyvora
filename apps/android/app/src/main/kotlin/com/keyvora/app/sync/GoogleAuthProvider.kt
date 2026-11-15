package com.keyvora.app.sync

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import com.google.android.gms.auth.GoogleAuthUtil
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.common.api.Scope
import com.google.android.gms.tasks.Task
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * OAuth for Drive via Google Identity Services `AuthorizationClient` (ADR-008): scope `drive.appdata` only, no client
 * secret in the APK. Requires an *Android* OAuth client (package `com.keyvora.app` + signing SHA-1) in the SAME Google
 * Cloud project as the extension's web client, otherwise both clients do not share `appDataFolder`
 * (see infrastructure/google-drive/README.md). Access tokens stay inside Google Play services and this process'
 * memory for the duration of a request; they are never stored or logged.
 */
class GoogleAuthProvider(private val context: Context) : AccessTokenProvider {

    sealed interface Interactive {
        /** Already authorized: nothing to show. */
        data object Granted : Interactive

        /** Launch [intentSender] (StartIntentSenderForResult) and pass the result to [completeInteractive]. */
        class NeedsConsent(val intentSender: IntentSender) : Interactive
    }

    private fun request(): AuthorizationRequest =
        AuthorizationRequest.builder().setRequestedScopes(listOf(Scope(GoogleDriveRemoteStore.SCOPE_DRIVE_APPDATA))).build()

    /** Starts the user-facing authorization (account picker + consent if needed). */
    suspend fun beginInteractive(activity: Activity): Interactive {
        val result = try {
            Identity.getAuthorizationClient(activity).authorize(request()).await()
        } catch (e: ApiException) {
            throw RemoteException(RemoteErrorCode.AUTH_REQUIRED, cause = e)
        }
        val pending = result.pendingIntent
        return if (result.hasResolution() && pending != null) Interactive.NeedsConsent(pending.intentSender) else Interactive.Granted
    }

    /** @return true when the consent screen granted the scope. */
    fun completeInteractive(data: Intent?): Boolean = try {
        val r: AuthorizationResult = Identity.getAuthorizationClient(context).getAuthorizationResultFromIntent(data)
        r.accessToken != null && r.grantedScopes.contains(GoogleDriveRemoteStore.SCOPE_DRIVE_APPDATA)
    } catch (_: ApiException) {
        false
    }

    override suspend fun accessToken(): String {
        val result = try {
            Identity.getAuthorizationClient(context).authorize(request()).await()
        } catch (e: ApiException) {
            throw RemoteException(RemoteErrorCode.AUTH_REQUIRED, cause = e)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw RemoteException(RemoteErrorCode.NETWORK, cause = e)
        }
        if (result.hasResolution()) throw RemoteException(RemoteErrorCode.AUTH_REQUIRED)
        return result.accessToken ?: throw RemoteException(RemoteErrorCode.AUTH_REQUIRED)
    }

    override suspend fun invalidate(token: String) {
        withContext(Dispatchers.IO) {
            try {
                GoogleAuthUtil.clearToken(context, token)
            } catch (_: Exception) {
                // Best effort: a stale cached token only costs another 401 → AUTH_REQUIRED.
            }
        }
    }
}

suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { cont ->
    addOnSuccessListener { cont.resume(it) }
    addOnFailureListener { cont.resumeWithException(it) }
    addOnCanceledListener { cont.cancel() }
}

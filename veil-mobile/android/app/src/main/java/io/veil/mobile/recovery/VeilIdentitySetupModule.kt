package io.veil.mobile.recovery

import android.app.Activity
import android.content.Intent
import com.facebook.react.bridge.ActivityEventListener
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import io.veil.mobile.MainActivity
import io.veil.mobile.runtime.VeilMobileRuntime
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Non-secret React Native launcher and durable-result reconciler. */
internal class VeilIdentitySetupModule(
  context: ReactApplicationContext,
  private val runtime: VeilMobileRuntime,
  private val journal: NativeIdentitySetupJournal,
) : ReactContextBaseJavaModule(context), ActivityEventListener, LifecycleEventListener {
  private data class PendingSetup(
    val id: Long,
    val mode: RecoveryMode,
    val promise: Promise,
    val requestCode: Int,
    var record: NativeIdentitySetupJournalRecord? = null,
    var lease: NativeIdentitySetupCoordinator.Lease? = null,
    var launched: Boolean = false,
  )

  private data class PreparedSetup(
    val record: NativeIdentitySetupJournalRecord,
    val lease: NativeIdentitySetupCoordinator.Lease,
  )

  private data class ObservedCorrelation(
    val attemptId: UUID,
    val processIncarnationId: UUID,
  )

  private class BeginPreparationFailure(val bridgeCode: String) : Exception()

  private val lock = Any()
  private val nextId = AtomicLong(1)
  private val hostResumed = AtomicBoolean(false)
  private val reconciliationScheduled = AtomicBoolean(false)
  private val settlementListener = NativeIdentitySetupCoordinator.SettlementListener {
    scheduleReconciliation()
  }
  private val reconciler = NativeIdentitySetupReconciler(
    journal = journal,
    coordinatorAttemptState = { record ->
      NativeIdentitySetupCoordinator.queryCorrelation(
        record.attemptId,
        record.processIncarnationId,
      ).toReconcilerState()
    },
    readStrictVaultPresence = runtime::verifyIdentityPresence,
  )

  private var pending: PendingSetup? = null
  private val pendingReconciliationPromises = mutableListOf<Promise>()
  private var observedCorrelation: ObservedCorrelation? = null
  private var invalidated = false

  init {
    context.addActivityEventListener(this)
    context.addLifecycleEventListener(this)
  }

  override fun getName(): String = "VeilIdentitySetup"

  @ReactMethod
  fun beginNativeIdentitySetup(mode: String, promise: Promise) {
    val parsedMode = RecoveryMode.fromBridge(mode)
    if (parsedMode == null) {
      promise.reject(ERROR_MODE, PUBLIC_UNAVAILABLE)
      return
    }

    val activity = currentActivity
    if (!isUsableForegroundActivity(activity)) {
      promise.reject(ERROR_ACTIVITY, PUBLIC_UNAVAILABLE)
      return
    }
    requireNotNull(activity)

    val request = synchronized(lock) {
      if (invalidated) {
        null
      } else if (pending != null) {
        PendingSetup(
          id = INVALID_PENDING_ID,
          mode = parsedMode,
          promise = promise,
          requestCode = INVALID_REQUEST_CODE,
        )
      } else {
        PendingSetup(
          id = nextId.getAndIncrement(),
          mode = parsedMode,
          promise = promise,
          requestCode = allocateRequestCode(),
        ).also { pending = it }
      }
    }
    if (request == null) {
      promise.reject(ERROR_ACTIVITY, PUBLIC_UNAVAILABLE)
      return
    }
    if (request.id == INVALID_PENDING_ID) {
      promise.reject(ERROR_BUSY, PUBLIC_UNAVAILABLE)
      return
    }

    runtime.execute { prepareAndLaunch(request, activity) }
  }

  /**
   * Resolves one retained, diagnostic-free native receipt. IN_PROGRESS and a
   * background lifecycle epoch deliberately keep this Promise pending; a
   * payload-free coordinator wakeup or host resume retries the authority read.
   */
  @ReactMethod
  fun reconcileNativeIdentitySetup(promise: Promise) {
    val unavailable = synchronized(lock) {
      if (invalidated) {
        true
      } else {
        pendingReconciliationPromises += promise
        false
      }
    }
    if (unavailable) {
      promise.resolve(unconfirmedWritableMap())
      return
    }
    scheduleReconciliation()
  }

  override fun onActivityResult(
    activity: Activity,
    requestCode: Int,
    resultCode: Int,
    data: Intent?,
  ) {
    val expected = synchronized(lock) { pending }
    val lease = expected?.lease ?: return
    if (requestCode != expected.requestCode) return
    if (classifyResult(
      expectedRequestCode = expected.requestCode,
      expectedLease = lease,
      requestCode = requestCode,
      resultCode = resultCode,
      hasResultData = data != null,
      returnedLeaseId = data?.let(RecoveryActivity::resultLeaseId),
      returnedAttemptId = data?.let(RecoveryActivity::resultAttemptId),
      returnedProcessIncarnationId =
        data?.let(RecoveryActivity::resultProcessIncarnationId),
      returnedOutcome = data?.let(RecoveryActivity::resultOutcome),
    ) == null) return

    // The Activity result is only an exact-tuple wake hint. Journal + vault
    // reconciliation remains the sole authority for the Promise outcome.
    NativeIdentitySetupCoordinator.release(lease)
    scheduleReconciliation()
  }

  override fun onNewIntent(intent: Intent) = Unit

  override fun onHostResume() {
    hostResumed.set(true)
    scheduleReconciliation()
  }

  override fun onHostPause() {
    hostResumed.set(false)
  }

  override fun onHostDestroy() {
    hostResumed.set(false)
  }

  override fun invalidate() {
    hostResumed.set(false)
    val request: PendingSetup?
    val reconcilePromises: List<Promise>
    val observed: ObservedCorrelation?
    synchronized(lock) {
      invalidated = true
      request = pending
      pending = null
      reconcilePromises = pendingReconciliationPromises.toList()
      pendingReconciliationPromises.clear()
      observed = observedCorrelation
      observedCorrelation = null
    }

    observed?.removeSettlementListener()
    reconcilePromises.forEach { it.resolve(unconfirmedWritableMap()) }
    request?.let { abandoned ->
      val prepared = abandoned.preparedOrNull()
      when {
        prepared == null -> abandoned.promise.reject(ERROR_ACTIVITY, PUBLIC_UNAVAILABLE)
        abandoned.launched -> NativeIdentitySetupCoordinator.abandonClient(prepared.lease)
        else -> runtime.execute {
          val clean = rollbackPrepared(prepared)
          abandoned.promise.reject(
            if (clean) ERROR_ACTIVITY else ERROR_BUSY,
            PUBLIC_UNAVAILABLE,
          )
        }
      }
    }

    reactApplicationContext.removeActivityEventListener(this)
    reactApplicationContext.removeLifecycleEventListener(this)
    super.invalidate()
  }

  private fun prepareAndLaunch(request: PendingSetup, activity: Activity) {
    var created: PreparedSetup? = null
    try {
      val prepared = runtime.withForegroundIdentitySetupAuthority {
        prepareJournalForExplicitAttempt()
        val record = journal.begin(request.mode.toJournalMode())
        val lease = NativeIdentitySetupCoordinator.acquire(
          record.attemptId,
          record.processIncarnationId,
        )
        if (lease == null) {
          terminalizePrepared(record)
          throw BeginPreparationFailure(ERROR_BUSY)
        }
        PreparedSetup(record, lease).also { created = it }
      }

      if (prepared == null) {
        val clean = created?.let(::rollbackPrepared) ?: true
        rejectReservedRequest(
          request.id,
          if (clean) ERROR_ACTIVITY else ERROR_BUSY,
        )
        return
      }
      if (!installPrepared(request.id, prepared)) {
        rollbackPrepared(prepared)
        return
      }

      scheduleReconciliation()
      try {
        activity.runOnUiThread { launchPrepared(request.id, activity) }
      } catch (_: Throwable) {
        failUnlaunchedRequest(request.id, ERROR_LAUNCH)
      }
    } catch (failure: BeginPreparationFailure) {
      val clean = created?.let(::rollbackPrepared) ?: true
      rejectReservedRequest(
        request.id,
        if (clean) failure.bridgeCode else ERROR_BUSY,
      )
    } catch (_: Throwable) {
      created?.let(::rollbackPrepared)
      rejectReservedRequest(request.id, ERROR_BUSY)
    }
  }

  /** Runs inside the runtime foreground epoch and coordinator barrier. */
  private fun prepareJournalForExplicitAttempt() {
    val existing = reconciler.reconcile()
    when (existing.status) {
      NativeIdentitySetupReconciliationStatus.NONE -> {
        // A missing journal says nothing about the write-once identity vault.
        // Never open a replacement ceremony over an existing local account.
        if (runtime.verifyIdentityPresence()) throw BeginPreparationFailure(ERROR_BUSY)
      }
      NativeIdentitySetupReconciliationStatus.USER_CANCELLED,
      NativeIdentitySetupReconciliationStatus.INTERRUPTED,
      -> {
        val correlation = existing.correlation
          ?: throw BeginPreparationFailure(ERROR_BUSY)
        val terminal = journal.readOrNull()
          ?: throw BeginPreparationFailure(ERROR_BUSY)
        if (
          terminal.phase != NativeIdentitySetupJournalPhase.TERMINAL ||
            terminal.attemptId != correlation.attemptId ||
            terminal.processIncarnationId != correlation.processIncarnationId ||
            terminal.revision != correlation.revision ||
            terminal.mode != existing.mode
        ) {
          throw BeginPreparationFailure(ERROR_BUSY)
        }
        // Clear the worker-free coordinator tombstone first. A crash between
        // these operations leaves the durable terminal journal recoverable;
        // the inverse order could strand an unaddressable process slot.
        NativeIdentitySetupCoordinator.consumeSettledCorrelation(
          correlation.attemptId,
          correlation.processIncarnationId,
        )
        journal.clearTerminal(terminal)
      }
      NativeIdentitySetupReconciliationStatus.IN_PROGRESS,
      NativeIdentitySetupReconciliationStatus.COMMITTED,
      NativeIdentitySetupReconciliationStatus.UNCONFIRMED,
      -> throw BeginPreparationFailure(ERROR_BUSY)
    }
  }

  private fun installPrepared(requestId: Long, prepared: PreparedSetup): Boolean =
    synchronized(lock) {
      val current = pending
      if (invalidated || current?.id != requestId) {
        false
      } else {
        current.record = prepared.record
        current.lease = prepared.lease
        true
      }
    }

  private fun launchPrepared(requestId: Long, activity: Activity) {
    var launchFailed = false
    synchronized(lock) {
      val current = pending
      val record = current?.record
      val lease = current?.lease
      if (invalidated || current?.id != requestId || record == null || lease == null) return
      if (currentActivity !== activity || !isUsableForegroundActivity(activity)) {
        launchFailed = true
      } else {
        try {
          activity.startActivityForResult(
            RecoveryActivity.intent(activity, current.mode, lease),
            current.requestCode,
          )
          current.launched = true
        } catch (_: Throwable) {
          launchFailed = true
        }
      }
    }
    if (launchFailed) failUnlaunchedRequest(requestId, ERROR_LAUNCH)
  }

  private fun failUnlaunchedRequest(requestId: Long, preferredCode: String) {
    val request = takePending(requestId) ?: return
    val prepared = request.preparedOrNull()
    runtime.execute {
      val clean = prepared?.let(::rollbackPrepared) ?: true
      request.promise.reject(if (clean) preferredCode else ERROR_BUSY, PUBLIC_UNAVAILABLE)
    }
  }

  private fun rejectReservedRequest(requestId: Long, code: String) {
    takePending(requestId)?.promise?.reject(code, PUBLIC_UNAVAILABLE)
  }

  private fun rollbackPrepared(prepared: PreparedSetup): Boolean {
    val journalSettled = terminalizePrepared(prepared.record)
    NativeIdentitySetupCoordinator.release(prepared.lease)
    return journalSettled
  }

  private fun terminalizePrepared(record: NativeIdentitySetupJournalRecord): Boolean =
    try {
      journal.transition(
        expected = record,
        nextPhase = NativeIdentitySetupJournalPhase.TERMINAL,
        outcome = NativeIdentitySetupJournalOutcome.INTERRUPTED,
      )
      true
    } catch (_: Throwable) {
      try {
        val current = journal.readOrNull()
        current != null &&
          record.isAllowedSuccessor(current) &&
          current.phase == NativeIdentitySetupJournalPhase.TERMINAL &&
          current.outcome == NativeIdentitySetupJournalOutcome.INTERRUPTED
      } catch (_: Throwable) {
        false
      }
    }

  private fun scheduleReconciliation() {
    if (!reconciliationScheduled.compareAndSet(false, true)) return
    runtime.execute {
      reconciliationScheduled.set(false)
      runReconciliation()
    }
  }

  private fun runReconciliation() {
    val hasWaiter = synchronized(lock) {
      if (invalidated) return
      pendingReconciliationPromises.isNotEmpty() || pending?.preparedOrNull() != null
    }
    if (!hasWaiter) return

    var result = try {
      runtime.reconcileIdentitySetup(reconciler)
    } catch (_: Throwable) {
      NativeIdentitySetupReconciliationResult(
        status = NativeIdentitySetupReconciliationStatus.UNCONFIRMED,
        correlation = null,
        mode = null,
      )
    } ?: return

    // RecoveryActivity persists TERMINAL before returning/detaching. During
    // that narrow window the exact READY coordinator is still IN_PROGRESS, so
    // the pure policy correctly says UNCONFIRMED. Do not publish that transient
    // classification: park on the payload-free settlement wakeup. If the
    // coordinator settled just after the policy snapshot, recompute once; a
    // second UNCONFIRMED is a stable fail-closed result (for example vault I/O).
    if (result.status == NativeIdentitySetupReconciliationStatus.UNCONFIRMED) {
      val correlation = result.correlation
      if (correlation != null) {
        val state = NativeIdentitySetupCoordinator.queryCorrelation(
          correlation.attemptId,
          correlation.processIncarnationId,
        )
        if (shouldAwaitSettlement(result.status, true, state)) {
          observeSettlement(result)
          return
        }
        if (state != NativeIdentitySetupCoordinator.ReconciliationState.CONFLICT) {
          result = try {
            runtime.reconcileIdentitySetup(reconciler)
          } catch (_: Throwable) {
            result
          } ?: return
        }
      }
    }

    if (result.status == NativeIdentitySetupReconciliationStatus.IN_PROGRESS) {
      observeSettlement(result)
      return
    }
    if (result.status == NativeIdentitySetupReconciliationStatus.UNCONFIRMED) {
      val correlation = result.correlation
      if (correlation != null) {
        val state = NativeIdentitySetupCoordinator.queryCorrelation(
            correlation.attemptId,
            correlation.processIncarnationId,
          )
        if (shouldAwaitSettlement(result.status, true, state)) {
          observeSettlement(result)
          return
        }
      }
    }

    clearObservedSettlement()
    if (shouldConsumeCoordinatorTombstone(result.status)) {
      result.correlation?.let { correlation ->
        NativeIdentitySetupCoordinator.consumeSettledCorrelation(
          correlation.attemptId,
          correlation.processIncarnationId,
        )
      }
    }

    val beginRequest: PendingSetup?
    val reconcilePromises: List<Promise>
    synchronized(lock) {
      beginRequest = pending?.takeIf { it.preparedOrNull() != null }
      if (beginRequest != null) pending = null
      reconcilePromises = pendingReconciliationPromises.toList()
      pendingReconciliationPromises.clear()
    }

    beginRequest?.let { settleBeginPromise(it, result) }
    reconcilePromises.forEach { promise -> promise.resolve(result.toWritableMap()) }
  }

  private fun settleBeginPromise(
    request: PendingSetup,
    result: NativeIdentitySetupReconciliationResult,
  ) {
    val prepared = request.preparedOrNull()
    val resultCorrelation = result.correlation
    val correlationMatches =
      prepared != null &&
        resultCorrelation != null &&
        resultCorrelation.attemptId == prepared.record.attemptId &&
        resultCorrelation.processIncarnationId == prepared.record.processIncarnationId &&
        result.mode == prepared.record.mode
    when {
      correlationMatches && result.status == NativeIdentitySetupReconciliationStatus.COMMITTED ->
        request.promise.resolve(NativeIdentitySetupOutcome.COMMITTED.bridgeValue)
      correlationMatches &&
        result.status == NativeIdentitySetupReconciliationStatus.USER_CANCELLED ->
        request.promise.resolve(NativeIdentitySetupOutcome.USER_CANCELLED.bridgeValue)
      correlationMatches &&
        result.status == NativeIdentitySetupReconciliationStatus.INTERRUPTED ->
        request.promise.resolve(NativeIdentitySetupOutcome.INTERRUPTED.bridgeValue)
      else -> {
        if (prepared != null) {
          if (request.launched) {
            NativeIdentitySetupCoordinator.abandonClient(prepared.lease)
          } else {
            NativeIdentitySetupCoordinator.release(prepared.lease)
          }
        }
        request.promise.reject(ERROR_BUSY, PUBLIC_UNAVAILABLE)
      }
    }
  }

  private fun observeSettlement(result: NativeIdentitySetupReconciliationResult) {
    val correlation = result.correlation ?: return
    val desired = ObservedCorrelation(correlation.attemptId, correlation.processIncarnationId)
    var retry = false
    synchronized(lock) {
      if (invalidated || observedCorrelation == desired) return
      observedCorrelation?.removeSettlementListener()
      val state = NativeIdentitySetupCoordinator.registerSettlementListener(
        desired.attemptId,
        desired.processIncarnationId,
        settlementListener,
      )
      if (state == NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS) {
        observedCorrelation = desired
      } else {
        observedCorrelation = null
        retry = state != NativeIdentitySetupCoordinator.ReconciliationState.SETTLED
      }
    }
    if (retry) scheduleReconciliation()
  }

  private fun clearObservedSettlement() {
    val observed = synchronized(lock) {
      observedCorrelation.also { observedCorrelation = null }
    }
    observed?.removeSettlementListener()
  }

  private fun ObservedCorrelation.removeSettlementListener() {
    NativeIdentitySetupCoordinator.removeSettlementListener(
      attemptId,
      processIncarnationId,
      settlementListener,
    )
  }

  private fun PendingSetup.preparedOrNull(): PreparedSetup? {
    val preparedRecord = record ?: return null
    val preparedLease = lease ?: return null
    return PreparedSetup(preparedRecord, preparedLease)
  }

  private fun takePending(expectedId: Long): PendingSetup? = synchronized(lock) {
    val current = pending ?: return@synchronized null
    if (current.id != expectedId) return@synchronized null
    pending = null
    current
  }

  private fun isUsableForegroundActivity(activity: Activity?): Boolean =
    activity != null &&
      activity.javaClass == MainActivity::class.java &&
      !activity.isFinishing &&
      !activity.isDestroyed &&
      hostResumed.get() &&
      activity.hasWindowFocus()

  companion object {
    private const val REQUEST_CODE_MIN = 0x4000
    private const val REQUEST_CODE_MAX = 0x7ffe
    private const val INVALID_REQUEST_CODE = -1
    private const val INVALID_PENDING_ID = -1L
    private val nextRequestCode = AtomicInteger(REQUEST_CODE_MIN)
    private const val ERROR_MODE = "E_VEIL_SETUP_MODE"
    private const val ERROR_ACTIVITY = "E_VEIL_SETUP_ACTIVITY"
    private const val ERROR_BUSY = "E_VEIL_SETUP_BUSY"
    private const val ERROR_LAUNCH = "E_VEIL_SETUP_LAUNCH"
    private const val PUBLIC_UNAVAILABLE = "Secure identity setup is unavailable"

    /**
     * A valid different full tuple is stale and ignored. Once the expected
     * request code returns without a complete canonical tuple, it is consumed
     * only as an interruption wake hint; it can never claim durable success.
     */
    internal fun classifyResult(
      expectedRequestCode: Int,
      expectedLease: NativeIdentitySetupCoordinator.Lease,
      requestCode: Int,
      resultCode: Int,
      hasResultData: Boolean,
      returnedLeaseId: Long?,
      returnedAttemptId: UUID?,
      returnedProcessIncarnationId: UUID?,
      returnedOutcome: NativeIdentitySetupOutcome?,
    ): NativeIdentitySetupOutcome? {
      if (requestCode != expectedRequestCode) return null
      if (!hasResultData) return NativeIdentitySetupOutcome.INTERRUPTED
      val returnedTupleIsComplete =
        returnedLeaseId != null &&
          returnedLeaseId > 0L &&
          returnedAttemptId != null &&
          returnedProcessIncarnationId != null
      if (!returnedTupleIsComplete) return NativeIdentitySetupOutcome.INTERRUPTED
      if (
        returnedLeaseId != expectedLease.id ||
          returnedAttemptId != expectedLease.attemptId ||
          returnedProcessIncarnationId != expectedLease.ownerProcessIncarnationId
      ) {
        return null
      }
      return when {
        resultCode == Activity.RESULT_OK &&
          returnedOutcome == NativeIdentitySetupOutcome.COMMITTED ->
          NativeIdentitySetupOutcome.COMMITTED
        resultCode == Activity.RESULT_CANCELED &&
          returnedOutcome == NativeIdentitySetupOutcome.USER_CANCELLED ->
          NativeIdentitySetupOutcome.USER_CANCELLED
        resultCode == Activity.RESULT_CANCELED &&
          returnedOutcome == NativeIdentitySetupOutcome.INTERRUPTED ->
          NativeIdentitySetupOutcome.INTERRUPTED
        else -> NativeIdentitySetupOutcome.INTERRUPTED
      }
    }

    internal fun shouldAwaitSettlement(
      status: NativeIdentitySetupReconciliationStatus,
      hasCorrelation: Boolean,
      coordinatorState: NativeIdentitySetupCoordinator.ReconciliationState,
    ): Boolean =
      hasCorrelation &&
        coordinatorState == NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS &&
        (status == NativeIdentitySetupReconciliationStatus.IN_PROGRESS ||
          status == NativeIdentitySetupReconciliationStatus.UNCONFIRMED)

    internal fun shouldConsumeCoordinatorTombstone(
      status: NativeIdentitySetupReconciliationStatus,
    ): Boolean =
      status == NativeIdentitySetupReconciliationStatus.COMMITTED ||
        status == NativeIdentitySetupReconciliationStatus.USER_CANCELLED ||
        status == NativeIdentitySetupReconciliationStatus.INTERRUPTED

    private fun allocateRequestCode(): Int {
      while (true) {
        val current = nextRequestCode.get()
        val following = if (current >= REQUEST_CODE_MAX) REQUEST_CODE_MIN else current + 1
        if (nextRequestCode.compareAndSet(current, following)) return current
      }
    }
  }
}

internal fun RecoveryMode.toJournalMode(): NativeIdentitySetupJournalMode = when (this) {
  RecoveryMode.CREATE -> NativeIdentitySetupJournalMode.CREATE
  RecoveryMode.RESTORE -> NativeIdentitySetupJournalMode.RESTORE
}

private fun NativeIdentitySetupJournalMode.toWireMode(): String = when (this) {
  NativeIdentitySetupJournalMode.CREATE -> "create"
  NativeIdentitySetupJournalMode.RESTORE -> "restore"
}

private fun NativeIdentitySetupReconciliationStatus.toWireStatus(): String = when (this) {
  NativeIdentitySetupReconciliationStatus.NONE -> "none"
  NativeIdentitySetupReconciliationStatus.IN_PROGRESS -> "in_progress"
  NativeIdentitySetupReconciliationStatus.COMMITTED -> "committed"
  NativeIdentitySetupReconciliationStatus.USER_CANCELLED -> "user_cancelled"
  NativeIdentitySetupReconciliationStatus.INTERRUPTED -> "interrupted"
  NativeIdentitySetupReconciliationStatus.UNCONFIRMED -> "unconfirmed"
}

private fun NativeIdentitySetupReconciliationStatus.carriesCorrelation(): Boolean = when (this) {
  NativeIdentitySetupReconciliationStatus.NONE,
  NativeIdentitySetupReconciliationStatus.UNCONFIRMED -> false
  NativeIdentitySetupReconciliationStatus.IN_PROGRESS,
  NativeIdentitySetupReconciliationStatus.COMMITTED,
  NativeIdentitySetupReconciliationStatus.USER_CANCELLED,
  NativeIdentitySetupReconciliationStatus.INTERRUPTED -> true
}

private fun NativeIdentitySetupReconciliationResult.toWritableMap() = Arguments.createMap().apply {
  putString("status", status.toWireStatus())
  if (status.carriesCorrelation()) {
    val exactCorrelation = requireNotNull(correlation)
    val exactMode = requireNotNull(mode)
    putString("attemptId", exactCorrelation.attemptId.toString())
    putString("processIncarnationId", exactCorrelation.processIncarnationId.toString())
    putString("mode", exactMode.toWireMode())
  }
}

private fun NativeIdentitySetupCoordinator.ReconciliationState.toReconcilerState():
  NativeIdentitySetupCoordinatorAttemptState = when (this) {
    NativeIdentitySetupCoordinator.ReconciliationState.IN_PROGRESS ->
      NativeIdentitySetupCoordinatorAttemptState.IN_PROGRESS
    NativeIdentitySetupCoordinator.ReconciliationState.SETTLED ->
      NativeIdentitySetupCoordinatorAttemptState.SETTLED
    NativeIdentitySetupCoordinator.ReconciliationState.ABSENT ->
      NativeIdentitySetupCoordinatorAttemptState.ABSENT
    NativeIdentitySetupCoordinator.ReconciliationState.CONFLICT ->
      NativeIdentitySetupCoordinatorAttemptState.CONFLICT
  }

private fun unconfirmedWritableMap() = Arguments.createMap().apply {
  putString("status", "unconfirmed")
}

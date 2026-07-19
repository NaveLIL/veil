package io.veil.mobile.recovery

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.Button
import android.widget.GridLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Space
import android.widget.TextView
import io.veil.mobile.R
import io.veil.mobile.crypto.NativeIdentityVault
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-local, screenshot-proof recovery ceremony.
 *
 * Only a non-secret create/restore mode and process lease enter this Activity,
 * and only a non-secret terminal outcome plus lease correlation leaves it. Recovery words never
 * cross Intent, Bundle, React Native, clipboard, autofill, accessibility, or the system IME.
 */
internal class RecoveryActivity : Activity(), NativeIdentitySetupCoordinator.Ceremony {
  private val terminal = AtomicBoolean(false)
  private val commitStarted = AtomicBoolean(false)
  private val foregroundGate = RecoveryForegroundGate()
  private val setupActionGuard = RecoverySetupActionGuard(ADVANCING_ACTION_DEBOUNCE_MS)
  private var pendingMode: RecoveryMode? = null
  private var controller: RecoveryFlowController? = null
  private var dictionary: RecoveryWordDictionary? = null
  private var provisioner: NativeIdentityProvisioner? = null
  private var sensitiveRoot: ViewGroup? = null
  private var secureScroll: ScrollView? = null
  private var renderedStage: RecoveryStage? = null
  private var activeRenderGeneration = 0L
  private var backCallback: Any? = null
  private var setupLease: NativeIdentitySetupCoordinator.Lease? = null
  private var coordinatorAttached = false
  private var transactionUi = TransactionUi.SETUP
  private var resumed = false
  private var windowFocused = false
  private var interactive = false

  override fun onCreate(savedInstanceState: Bundle?) {
    protectWindowBeforeContent()
    super.onCreate(null)
    RecoveryContentCapture.disableForActivity(this)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      setRecentsScreenshotEnabled(false)
    }
    title = getString(R.string.recovery_activity_label)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      val callback = Api33Back.register(this) { handleBack() }
      backCallback = callback
    }

    val mode = intent?.getStringExtra(EXTRA_MODE)?.let(RecoveryMode::fromBridge)
    val leaseId = intent?.getLongExtra(EXTRA_LEASE_ID, INVALID_LEASE_ID) ?: INVALID_LEASE_ID
    if (mode == null || leaseId <= 0) {
      finishInterrupted()
      return
    }
    val lease = NativeIdentitySetupCoordinator.Lease(leaseId)
    setupLease = lease
    when (NativeIdentitySetupCoordinator.attachOrAdopt(lease, this)) {
      NativeIdentitySetupCoordinator.Attachment.OWNER -> coordinatorAttached = true
      NativeIdentitySetupCoordinator.Attachment.COMMITTING -> {
        coordinatorAttached = true
        commitStarted.set(true)
        transactionUi = TransactionUi.COMMITTING
        return
      }
      NativeIdentitySetupCoordinator.Attachment.COMMITTED -> {
        coordinatorAttached = true
        finishCommitted()
        return
      }
      NativeIdentitySetupCoordinator.Attachment.FAILED -> {
        coordinatorAttached = true
        commitStarted.set(true)
        transactionUi = TransactionUi.FAILED
        return
      }
      NativeIdentitySetupCoordinator.Attachment.REJECTED -> {
        NativeIdentitySetupCoordinator.discardRejected(lease)
        finishInterrupted()
        return
      }
    }

    try {
      val identityVault = NativeIdentityVault(applicationContext)
      if (identityVault.hasIdentity()) {
        finishAlreadyProvisioned()
        return
      }
      // Secret draft creation is delayed until this Activity is both resumed
      // and window-focused. onCreate alone never materializes recovery words.
      pendingMode = mode
    } catch (_: Throwable) {
      // Do not reflect crypto, word-list, or storage diagnostics into another
      // Activity. The bridge receives only the interrupted terminal status.
      finishInterrupted()
    }
  }

  override fun onResume() {
    super.onResume()
    resumed = true
    reconcileInteractive(cancelOnLoss = false)
  }

  override fun onPause() {
    resumed = false
    reconcileInteractive(cancelOnLoss = true)
    super.onPause()
  }

  override fun onStop() {
    reconcileInteractive(cancelOnLoss = true)
    super.onStop()
  }

  override fun onDestroy() {
    foregroundGate.markBackground()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      backCallback?.let { Api33Back.unregister(this, it) }
    }
    backCallback = null
    clearSensitiveViews()
    controller?.close()
    controller = null
    dictionary = null
    provisioner = null
    pendingMode = null
    if (coordinatorAttached) {
      setupLease?.let { lease -> NativeIdentitySetupCoordinator.detach(lease, this) }
    }
    coordinatorAttached = false
    setupLease = null
    super.onDestroy()
  }

  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    // RecoveryActivity handles rotation itself, so the native draft and fixed
    // mutable arrays live only in this process and never enter saved state.
    if (interactive) renderCurrentUi()
  }

  override fun onSaveInstanceState(outState: Bundle) {
    // Let Activity satisfy its lifecycle contract, then erase the hierarchy
    // state it collected. Recreation starts a fresh native draft.
    super.onSaveInstanceState(outState)
    outState.clear()
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    windowFocused = hasFocus
    reconcileInteractive(cancelOnLoss = !hasFocus && interactive)
  }

  override fun onCoordinatorEvent(event: NativeIdentitySetupCoordinator.CoordinatorEvent) {
    runOnUiThread {
      if (isDestroyed || terminal.get()) return@runOnUiThread
      when (event) {
        NativeIdentitySetupCoordinator.CoordinatorEvent.REVOKED -> {
          if (transactionUi == TransactionUi.COMMITTING) {
            handleVisibilityLoss()
          } else {
            finishInterrupted()
          }
        }
        NativeIdentitySetupCoordinator.CoordinatorEvent.COMMITTED -> finishCommitted()
        NativeIdentitySetupCoordinator.CoordinatorEvent.FAILED -> {
          transactionUi = TransactionUi.FAILED
          clearSensitiveViews()
          if (interactive) renderCurrentUi()
        }
      }
    }
  }

  @Deprecated("Handled for Android 12 and lower; API 33+ uses OnBackInvokedCallback")
  override fun onBackPressed() {
    handleBack()
  }

  override fun dispatchTouchEvent(event: MotionEvent): Boolean {
    val obscured = event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0
    val partiallyObscured =
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
        event.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
    if (obscured || partiallyObscured) return false
    return super.dispatchTouchEvent(event)
  }

  private fun protectWindowBeforeContent() {
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      window.setHideOverlayWindows(true)
    }
    window.decorView.filterTouchesWhenObscured = true
  }

  private fun renderCurrentUi() {
    if (!interactive || terminal.get()) return
    when (transactionUi) {
      TransactionUi.SETUP -> renderSetup()
      TransactionUi.COMMITTING -> renderTransactionUi(::renderCommitting)
      TransactionUi.FAILED -> renderTransactionUi(::renderFailed)
    }
  }

  private fun renderTransactionUi(render: (LinearLayout) -> Unit) {
    renderedStage = null
    val root = beginSecureRoot()
    root.addView(brandHeader())
    root.addView(space(20))
    val island = newStageIsland()
    root.addView(island, islandLayout())
    render(island)
    installSecureRoot(root)
  }

  private fun renderSetup() {
    if (!ensureSetupInitialized()) return
    if (!resumed || !windowFocused || !window.decorView.hasWindowFocus()) {
      interactive = false
      windowFocused = false
      handleVisibilityLoss()
      return
    }
    val flow = controller ?: return
    val words = dictionary ?: return
    val stage = flow.stage
    val retainedScrollY = RecoveryUiSafety.retainedScrollY(
      previousStage = renderedStage,
      nextStage = stage,
      currentScrollY = secureScroll?.scrollY ?: 0,
    )
    val root = beginSecureRoot()
    val generation = activeRenderGeneration
    root.addView(brandHeader())
    root.addView(space(20))
    val island = newStageIsland()
    root.addView(island, islandLayout())

    when (stage) {
      RecoveryStage.CREATE_REVIEW -> renderCreateReview(island, flow, words, generation)
      RecoveryStage.CREATE_CHALLENGE -> renderCreateChallenge(island, flow, words, generation)
      RecoveryStage.RESTORE_ENTRY -> renderRestoreEntry(island, flow, words, generation)
      RecoveryStage.READY_TO_COMMIT -> renderReady(island, flow, generation)
      RecoveryStage.COMMITTING -> renderCommitting(island)
      RecoveryStage.CLOSED -> renderFailed(island)
      RecoveryStage.COMMITTED -> Unit
    }

    renderedStage = stage
    installSecureRoot(root, retainedScrollY)
  }

  private fun ensureSetupInitialized(): Boolean {
    if (controller != null) return true
    val mode = pendingMode ?: return false
    return try {
      val identityVault = NativeIdentityVault(applicationContext)
      if (identityVault.hasIdentity()) {
        finishAlreadyProvisioned()
        false
      } else {
        val loadedDictionary = PinnedBip39EnglishWords(applicationContext)
        dictionary = loadedDictionary
        controller = RecoveryFlowController(
          UniFfiRecoveryDraftFactory.create(mode),
          loadedDictionary,
        )
        provisioner = NativeIdentityProvisioner(
          vault = identityVault,
          foregroundGate = foregroundGate,
        )
        pendingMode = null
        true
      }
    } catch (_: Throwable) {
      finishTerminal(NativeIdentitySetupOutcome.INTERRUPTED)
      false
    }
  }

  private fun newSecureRoot(): LinearLayout = LinearLayout(this).apply {
    id = R.id.recovery_secure_root
    orientation = LinearLayout.VERTICAL
    gravity = Gravity.CENTER_HORIZONTAL
    applyRecoveryInsets()
    setBackgroundColor(color(R.color.recoveryBackground))
    excludeFromAutofill(hideDescendants = true)
    excludeFromContentCapture(hideDescendants = true)
    filterTouchesWhenObscured = true
  }

  /** Registers the root before any secret child or callback can be constructed. */
  private fun beginSecureRoot(): LinearLayout {
    clearSensitiveViews()
    return newSecureRoot().also { root -> sensitiveRoot = root }
  }

  @Suppress("DEPRECATION")
  private fun View.applyRecoveryInsets() {
    val baseHorizontal = dp(ROOT_HORIZONTAL_INSET_DP)
    val baseTop = dp(20)
    val baseBottom = dp(40)
    setPadding(baseHorizontal, baseTop, baseHorizontal, baseBottom)
    setOnApplyWindowInsetsListener { view, insets ->
      val left: Int
      val top: Int
      val right: Int
      val bottom: Int
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        val safeInsets = insets.getInsets(
          WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout(),
        )
        left = safeInsets.left
        top = safeInsets.top
        right = safeInsets.right
        bottom = safeInsets.bottom
      } else {
        val cutoutSafe =
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) Api28Cutout.safeInsets(insets) else null
        left = maxOf(insets.systemWindowInsetLeft, cutoutSafe?.left ?: 0)
        top = maxOf(insets.systemWindowInsetTop, cutoutSafe?.top ?: 0)
        right = maxOf(insets.systemWindowInsetRight, cutoutSafe?.right ?: 0)
        bottom = maxOf(insets.systemWindowInsetBottom, cutoutSafe?.bottom ?: 0)
      }
      view.setPadding(
        baseHorizontal + left,
        baseTop + top,
        baseHorizontal + right,
        baseBottom + bottom,
      )
      insets
    }
  }

  private fun newStageIsland(): LinearLayout = RecoveryIslandLayout(
    context = this,
    maxWidthDp = ISLAND_MAX_WIDTH_DP,
  ).apply {
    id = R.id.recovery_stage_island
    orientation = LinearLayout.VERTICAL
    setPadding(dp(20), dp(22), dp(20), dp(22))
    background = roundedSurface(R.color.recoverySurface, 20, R.color.recoveryBorder)
    excludeFromAutofill(hideDescendants = true)
    excludeFromContentCapture(hideDescendants = true)
    filterTouchesWhenObscured = true
  }

  private fun islandLayout(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
    ViewGroup.LayoutParams.MATCH_PARENT,
    ViewGroup.LayoutParams.WRAP_CONTENT,
  ).apply {
    gravity = Gravity.CENTER_HORIZONTAL
  }

  private fun installSecureRoot(root: LinearLayout, retainedScrollY: Int = 0) {
    check(sensitiveRoot === root) { "secure recovery root ownership changed" }
    val scroll = ScrollView(this).apply {
      id = R.id.recovery_secure_scroll
      isFillViewport = true
      isSaveEnabled = false
      isVerticalScrollBarEnabled = false
      overScrollMode = View.OVER_SCROLL_NEVER
      addView(
        root,
        ViewGroup.LayoutParams(
          ViewGroup.LayoutParams.MATCH_PARENT,
          ViewGroup.LayoutParams.WRAP_CONTENT,
        ),
      )
    }
    secureScroll = scroll
    setContentView(scroll)
    restoreScrollBeforeFirstDraw(scroll, retainedScrollY)
  }

  private fun restoreScrollBeforeFirstDraw(scroll: ScrollView, retainedScrollY: Int) {
    if (retainedScrollY <= 0) return
    scroll.viewTreeObserver.addOnPreDrawListener(
      object : ViewTreeObserver.OnPreDrawListener {
        override fun onPreDraw(): Boolean {
          if (scroll.viewTreeObserver.isAlive) {
            scroll.viewTreeObserver.removeOnPreDrawListener(this)
          }
          if (secureScroll !== scroll || terminal.get()) return true
          val child = scroll.getChildAt(0) ?: return true
          val viewport = (scroll.height - scroll.paddingTop - scroll.paddingBottom).coerceAtLeast(0)
          val maxScrollY = (child.measuredHeight - viewport).coerceAtLeast(0)
          scroll.scrollTo(0, retainedScrollY.coerceIn(0, maxScrollY))
          return true
        }
      },
    )
  }

  private fun renderCreateReview(
    root: LinearLayout,
    flow: RecoveryFlowController,
    words: RecoveryWordDictionary,
    generation: Long,
  ) {
    root.addView(titleText(getString(R.string.recovery_create_title)))
    root.addView(bodyText(getString(R.string.recovery_create_intro)))
    root.addView(space(18))
    addRecoveryWordGrid(root, flow, words)
    root.addView(space(12))
    root.addView(privacyNotice())
    root.addView(space(24))
    root.addOwnedButton(primaryButton(getString(R.string.recovery_continue)) {
      performAdvancingSetupAction(generation) { flow.continueFromCreateReview() }
    })
    root.addView(space(10))
    root.addOwnedButton(cancelSetupButton(generation))
  }

  private fun renderCreateChallenge(
    root: LinearLayout,
    flow: RecoveryFlowController,
    words: RecoveryWordDictionary,
    generation: Long,
  ) {
    root.addView(titleText(getString(R.string.recovery_challenge_title)))
    root.addView(
      bodyText(
        getString(R.string.recovery_challenge_prompt, flow.challengePosition() + 1),
      ),
    )
    if (flow.issue == RecoveryIssue.WRONG_CHALLENGE_WORD) {
      root.addView(issueText(getString(R.string.recovery_wrong_word)))
    }
    root.addView(space(20))

    val secretChoices = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
      )
      importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
      excludeFromAutofill(hideDescendants = true)
      excludeFromContentCapture(hideDescendants = true)
    }
    root.addView(secretChoices)
    val choices = flow.challengeChoices()
    try {
      for (index in choices) {
        val button = secretChoiceButton(words.word(index), index) { chosen ->
          performAdvancingSetupAction(generation) { flow.chooseChallengeWord(chosen) }
        }
        try {
          secretChoices.addView(button)
        } catch (failure: Throwable) {
          button.wipe()
          throw failure
        }
        secretChoices.addView(space(10))
      }
    } finally {
      choices.fill(-1)
    }
    root.addView(privacyNotice())
    root.addView(space(18))
    root.addOwnedButton(cancelSetupButton(generation))
  }

  private fun renderRestoreEntry(
    root: LinearLayout,
    flow: RecoveryFlowController,
    words: RecoveryWordDictionary,
    generation: Long,
  ) {
    root.addView(titleText(getString(R.string.recovery_restore_title)))
    root.addView(bodyText(getString(R.string.recovery_restore_intro)))
    root.addView(space(12))
    root.addView(
      eyebrowText(
        getString(
          R.string.recovery_word_progress,
          flow.restorePosition() + 1,
          flow.wordCount(),
        ),
      ),
    )
    if (flow.issue == RecoveryIssue.INVALID_PHRASE) {
      root.addView(issueText(getString(R.string.recovery_invalid_phrase)))
    }
    root.addView(space(12))
    addRecoveryWordGrid(root, flow, words)
    root.addView(space(16))

    val secretInput = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
      )
      setPadding(dp(16), dp(14), dp(16), dp(14))
      background = roundedSurface(R.color.recoverySurfaceLow, 14, R.color.recoveryBorder)
      importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
      excludeFromAutofill(hideDescendants = true)
      excludeFromContentCapture(hideDescendants = true)
    }
    root.addView(secretInput)
    secretInput.addView(eyebrowText(getString(R.string.recovery_private_input)))
    val inputChars = flow.inputCopy()
    try {
      val inputView = RecoveryPrivateInputView(this, inputChars)
      try {
        secretInput.addView(
          inputView,
          LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
          ),
        )
      } catch (failure: Throwable) {
        inputView.wipe()
        throw failure
      }
    } finally {
      inputChars.fill('\u0000')
    }
    secretInput.addView(space(10))

    val suggestionRow = GridLayout(this).apply {
      columnCount = if (isLargeFont()) 1 else SUGGESTION_COLUMN_COUNT
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
      )
      importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
      excludeFromAutofill(hideDescendants = true)
      excludeFromContentCapture(hideDescendants = true)
    }
    secretInput.addView(suggestionRow)
    val suggestions = flow.suggestions(SUGGESTION_SLOT_COUNT)
    try {
      for (index in suggestions) {
        addSecretChoiceCell(
          suggestionRow,
          secretChoiceButton(words.word(index), index) { chosen ->
            performAdvancingSetupAction(generation) { flow.chooseImportWord(chosen) }
          },
        )
      }
      repeat(
        RecoveryUiSafety.placeholderCount(
          actualSuggestions = suggestions.size,
          reservedSlots = SUGGESTION_SLOT_COUNT,
        ),
      ) {
        addSecretChoiceCell(suggestionRow, secretChoicePlaceholder())
      }
    } finally {
      suggestions.fill(-1)
    }
    root.addView(space(14))
    addAlphabetKeyboard(root, flow, generation)
    root.addView(space(10))

    val actions = LinearLayout(this).apply {
      orientation = if (isLargeFont()) LinearLayout.VERTICAL else LinearLayout.HORIZONTAL
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
      )
    }
    root.addView(actions)
    val actionCell = if (isLargeFont()) fullWidthCell() else weightedCell()
    actions.addOwnedButton(
      secondaryButton(getString(R.string.recovery_erase)) {
        performSetupAction(generation) { flow.eraseInput() }
      },
      actionCell,
    )
    actions.addView(space(10))
    actions.addOwnedButton(
      secondaryButton(getString(R.string.recovery_clear)) {
        performSetupAction(generation) { while (flow.eraseInput()) Unit }
      },
      if (isLargeFont()) fullWidthCell() else weightedCell(),
    )
    root.addView(space(12))
    root.addView(privacyNotice())
    root.addView(space(18))
    root.addOwnedButton(cancelSetupButton(generation))
  }

  private fun renderReady(
    root: LinearLayout,
    flow: RecoveryFlowController,
    generation: Long,
  ) {
    root.addView(titleText(getString(R.string.recovery_ready_title)))
    root.addView(
      bodyText(
        getString(
          if (flow.mode == RecoveryMode.CREATE) {
            R.string.recovery_ready_body_create
          } else {
            R.string.recovery_ready_body_restore
          },
        ),
      ),
    )
    root.addView(space(28))
    root.addOwnedButton(
      primaryButton(
        getString(
          if (flow.mode == RecoveryMode.CREATE) {
            R.string.recovery_commit_create
          } else {
            R.string.recovery_commit_restore
          },
        ),
      ) {
        performAdvancingSetupAction(generation, renderAfterAction = false) { beginCommit() }
      },
    )
    root.addView(space(10))
    root.addOwnedButton(cancelSetupButton(generation))
  }

  private fun renderCommitting(root: LinearLayout) {
    root.gravity = Gravity.CENTER_HORIZONTAL
    root.addView(ProgressBar(this).apply {
      isIndeterminate = true
      importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
    })
    root.addView(space(24))
    root.addView(titleText(getString(R.string.recovery_committing_title)))
    root.addView(bodyText(getString(R.string.recovery_committing_body)))
  }

  private fun renderFailed(root: LinearLayout) {
    root.addView(titleText(getString(R.string.recovery_failed_title)))
    root.addView(bodyText(getString(R.string.recovery_failed_body)))
    root.addView(space(28))
    root.addOwnedButton(primaryButton(getString(R.string.recovery_close)) { finishInterrupted() })
  }

  private fun beginCommit() {
    val flow = controller ?: return
    val words = dictionary ?: return
    val identityProvisioner = provisioner ?: return
    val lease = setupLease ?: return
    if (!coordinatorAttached || !commitStarted.compareAndSet(false, true)) return

    var indices: IntArray? = null
    var work: NativeRecoveryCommitWork? = null
    try {
      indices = flow.copyIndicesForCommit()
      transactionUi = TransactionUi.COMMITTING
      renderCurrentUi()
      val ownedIndices = requireNotNull(indices)
      work = NativeRecoveryCommitWork(
        flow = flow,
        ownedIndices = ownedIndices,
        runner = NativeRecoveryCommitRunner(words, identityProvisioner),
      )
      // Keep the fallback reference until the owner object exists. If any
      // allocation above fails, the catch path still overwrites the copy.
      indices = null
      if (!NativeIdentitySetupCoordinator.beginCommit(lease, this, work)) {
        work.close()
        work = null
        controller = null
        dictionary = null
        provisioner = null
        transactionUi = TransactionUi.FAILED
        renderCurrentUi()
        return
      }
      // From this point the process coordinator is the sole owner of the
      // native draft, copied indices, and provisioning transaction.
      work = null
      controller = null
      dictionary = null
      provisioner = null
    } catch (_: Throwable) {
      indices?.fill(-1)
      work?.close()
      try {
        flow.markSetupFailed()
      } catch (_: Throwable) {
        // The work may already have closed the native draft.
      }
      controller = null
      dictionary = null
      provisioner = null
      transactionUi = TransactionUi.FAILED
      clearSensitiveViews()
      renderCurrentUi()
    }
  }

  private fun handleBack() {
    if (transactionUi == TransactionUi.COMMITTING) return
    if (transactionUi == TransactionUi.FAILED) {
      finishInterrupted()
      return
    }
    val flow = controller
    if (flow == null) {
      finishInterrupted()
      return
    }
    performSetupAction(activeRenderGeneration) {
      when (flow.handleBack()) {
        RecoveryBackResult.UPDATED -> Unit
        RecoveryBackResult.CANCEL -> finishUserCancelled()
        RecoveryBackResult.BLOCKED -> Unit
      }
    }
  }

  private fun performSetupAction(
    expectedGeneration: Long,
    renderAfterAction: Boolean = true,
    action: () -> Unit,
  ) {
    setupActionGuard.perform(
      expectedGeneration = expectedGeneration,
      currentGeneration = activeRenderGeneration,
      setupEnabled = !terminal.get() && transactionUi == TransactionUi.SETUP,
      advancing = false,
      nowMs = 0L,
      action = action,
      render = { if (renderAfterAction) renderCurrentUi() },
      failClosed = ::failSetupUi,
    )
  }

  private fun performAdvancingSetupAction(
    expectedGeneration: Long,
    renderAfterAction: Boolean = true,
    action: () -> Unit,
  ) {
    setupActionGuard.perform(
      expectedGeneration = expectedGeneration,
      currentGeneration = activeRenderGeneration,
      setupEnabled = !terminal.get() && transactionUi == TransactionUi.SETUP,
      advancing = true,
      nowMs = SystemClock.elapsedRealtime(),
      action = action,
      render = { if (renderAfterAction) renderCurrentUi() },
      failClosed = ::failSetupUi,
    )
  }

  private fun failSetupUi() {
    if (terminal.get() || transactionUi == TransactionUi.COMMITTING) return
    try {
      val failedController = controller
      controller = null
      dictionary = null
      provisioner = null
      transactionUi = TransactionUi.FAILED
      try {
        failedController?.markSetupFailed()
      } catch (_: Throwable) {
        try {
          failedController?.close()
        } catch (_: Throwable) {
          // The generic terminal UI still must not expose the native failure.
        }
      }
      clearSensitiveViews()
      if (interactive) {
        try {
          renderCurrentUi()
        } catch (_: Throwable) {
          forceFinishCancelledAfterUiFailure()
        }
      }
    } catch (_: Throwable) {
      forceFinishCancelledAfterUiFailure()
    }
  }

  /** Last-resort no-throw terminal path used only when even generic failure UI cannot render. */
  private fun forceFinishCancelledAfterUiFailure() {
    terminal.set(true)
    try {
      foregroundGate.markBackground()
    } catch (_: Throwable) {
      // Continue removing every remaining reference.
    }
    try {
      clearSensitiveViews()
    } catch (_: Throwable) {
      // clearSensitiveViews is no-throw by construction; retain the outer guard.
    }
    val abandonedController = controller
    controller = null
    dictionary = null
    provisioner = null
    pendingMode = null
    try {
      abandonedController?.close()
    } catch (_: Throwable) {
      // Native cleanup failure must not re-enter the main loop.
    }
    try {
      setTerminalResult(NativeIdentitySetupOutcome.INTERRUPTED)
    } catch (_: Throwable) {
      try {
        setResult(RESULT_CANCELED)
      } catch (_: Throwable) {
        // Activity teardown remains the final boundary.
      }
    }
    try {
      finish()
    } catch (_: Throwable) {
      // No recovery material or diagnostic is reflected outside this Activity.
    }
  }

  private fun finishInterrupted() {
    if (transactionUi == TransactionUi.COMMITTING) {
      handleVisibilityLoss()
      return
    }
    finishTerminal(NativeIdentitySetupOutcome.INTERRUPTED)
  }

  private fun finishUserCancelled() {
    if (transactionUi == TransactionUi.COMMITTING) return
    finishTerminal(NativeIdentitySetupOutcome.USER_CANCELLED)
  }

  private fun finishTerminal(outcome: NativeIdentitySetupOutcome) {
    check(outcome != NativeIdentitySetupOutcome.COMMITTED)
    if (!terminal.compareAndSet(false, true)) return
    foregroundGate.markBackground()
    clearSensitiveViews()
    controller?.close()
    controller = null
    setTerminalResult(outcome)
    finish()
  }

  private fun finishAlreadyProvisioned() {
    finishCommitted()
  }

  private fun finishCommitted() {
    if (!terminal.compareAndSet(false, true)) return
    foregroundGate.markBackground()
    clearSensitiveViews()
    setTerminalResult(NativeIdentitySetupOutcome.COMMITTED)
    finish()
  }

  private fun setTerminalResult(outcome: NativeIdentitySetupOutcome) {
    val resultCode =
      if (outcome == NativeIdentitySetupOutcome.COMMITTED) RESULT_OK else RESULT_CANCELED
    val result = Intent().putExtra(EXTRA_RESULT_OUTCOME, outcome.bridgeValue)
    val lease = setupLease
    if (lease != null) result.putExtra(EXTRA_RESULT_LEASE_ID, lease.id)
    setResult(resultCode, result)
  }

  private fun handleVisibilityLoss() {
    foregroundGate.markBackground()
    clearSensitiveViews()
    if (transactionUi == TransactionUi.COMMITTING) return
    if (!isChangingConfigurations && !isFinishing && !terminal.get()) {
      finishTerminal(NativeIdentitySetupOutcome.INTERRUPTED)
    }
  }

  private fun reconcileInteractive(cancelOnLoss: Boolean) {
    val shouldBeInteractive = resumed && windowFocused && !terminal.get()
    if (shouldBeInteractive) {
      interactive = true
      foregroundGate.markForeground()
      if (sensitiveRoot == null) renderCurrentUi()
      return
    }

    val lostInteractiveSession = interactive
    interactive = false
    if (lostInteractiveSession || cancelOnLoss) handleVisibilityLoss()
  }

  private fun brandHeader(): View {
    val stacked = isLargeFont()
    val row = LinearLayout(this).apply {
      orientation = if (stacked) LinearLayout.VERTICAL else LinearLayout.HORIZONTAL
      gravity = if (stacked) Gravity.CENTER else Gravity.CENTER_VERTICAL
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.WRAP_CONTENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
      ).apply {
        gravity = Gravity.CENTER_HORIZONTAL
      }
    }
    row.addView(
      PhaseShiftMarkView(this),
      LinearLayout.LayoutParams(dp(40), dp(40)),
    )
    row.addView(space(12))
    row.addView(eyebrowText(getString(R.string.recovery_brand)).apply {
      if (stacked) gravity = Gravity.CENTER
    })
    return row
  }

  private fun addRecoveryWordGrid(
    parent: ViewGroup,
    flow: RecoveryFlowController,
    words: RecoveryWordDictionary,
  ) {
    val ownedIndices = IntArray(flow.wordCount()) { position -> flow.wordIndex(position) }
    var grid: RecoveryPhraseGridView? = null
    var ownershipTransferred = false
    try {
      grid = RecoveryPhraseGridView(
        context = this,
        dictionary = words,
        ownedIndices = ownedIndices,
      ).apply {
        setPadding(dp(10), dp(10), dp(10), dp(10))
        layoutParams = LinearLayout.LayoutParams(
          ViewGroup.LayoutParams.MATCH_PARENT,
          ViewGroup.LayoutParams.WRAP_CONTENT,
        )
        tag = SECRET_VIEW_TAG
      }
      parent.addView(grid)
      ownershipTransferred = true
    } catch (failure: Throwable) {
      grid?.wipe()
      throw failure
    } finally {
      if (!ownershipTransferred) ownedIndices.fill(-1)
    }
  }

  private fun addAlphabetKeyboard(
    parent: ViewGroup,
    flow: RecoveryFlowController,
    generation: Long,
  ) {
    val grid = GridLayout(this).apply {
      columnCount = RecoveryUiSafety.alphabetColumns(
        screenWidthDp = resources.configuration.screenWidthDp,
        fontScale = resources.configuration.fontScale,
      )
      alignmentMode = GridLayout.ALIGN_BOUNDS
      useDefaultMargins = false
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
      )
    }
    parent.addView(grid)
    for (letter in 'A'..'Z') {
      val button = compactButton(letter.toString()) {
        performSetupAction(generation) { flow.appendInput(letter.lowercaseChar()) }
      }
      try {
        grid.addView(button, gridCell())
      } catch (failure: Throwable) {
        button.setOnClickListener(null)
        throw failure
      }
    }
  }

  private fun titleText(value: String): TextView = TextView(this).apply {
    text = value
    setTextColor(color(R.color.recoveryText))
    textSize = 26f
    typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    setLineSpacing(0f, 1.08f)
  }

  private fun bodyText(value: String): TextView = TextView(this).apply {
    text = value
    setTextColor(color(R.color.recoveryTextMuted))
    textSize = 15f
    setLineSpacing(0f, 1.25f)
    setPadding(0, dp(10), 0, 0)
  }

  private fun eyebrowText(value: String): TextView = TextView(this).apply {
    text = value
    setTextColor(color(R.color.recoveryAccent))
    textSize = 12f
    typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    letterSpacing = 0.08f
  }

  private fun privacyNotice(): TextView = bodyText(
    getString(R.string.recovery_accessibility_notice),
  ).apply {
    textSize = 13f
    setCompoundDrawablesWithIntrinsicBounds(android.R.drawable.ic_lock_lock, 0, 0, 0)
    compoundDrawablePadding = dp(8)
  }

  private fun issueText(value: String): TextView = bodyText(value).apply {
    setTextColor(color(R.color.recoveryDanger))
    announceForAccessibility(value)
  }

  private fun primaryButton(value: String, action: () -> Unit): Button =
    actionButton(
      value,
      R.color.recoveryPrimary,
      R.color.recoveryPrimaryPressed,
      R.color.recoveryPrimaryText,
      action,
    )

  private fun secondaryButton(value: String, action: () -> Unit): Button =
    actionButton(
      value,
      R.color.recoverySurfaceRaised,
      R.color.recoverySurfaceFocused,
      R.color.recoveryText,
      action,
    )

  private fun cancelSetupButton(generation: Long): Button =
    secondaryButton(getString(R.string.recovery_cancel)) {
      performSetupAction(generation, renderAfterAction = false) { finishUserCancelled() }
    }

  private fun secretChoiceButton(
    value: String,
    wordIndex: Int,
    action: (Int) -> Unit,
  ): RecoveryWordChoiceButton = RecoveryWordChoiceButton(this, value, wordIndex, action).apply {
    layoutParams = LinearLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT,
      ViewGroup.LayoutParams.WRAP_CONTENT,
    )
    tag = SECRET_VIEW_TAG
  }

  private fun secretChoicePlaceholder(): RecoveryWordChoiceButton =
    RecoveryWordChoiceButton(this, "", -1, null).apply {
      layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
      )
      visibility = View.INVISIBLE
      isClickable = false
      isFocusable = false
      setOnClickListener(null)
      tag = SECRET_VIEW_TAG
    }

  private fun addSecretChoiceCell(
    parent: GridLayout,
    button: RecoveryWordChoiceButton,
  ) {
    try {
      parent.addView(button, gridCell())
    } catch (failure: Throwable) {
      button.wipe()
      throw failure
    }
  }

  private fun compactButton(value: String, action: () -> Unit): Button =
    actionButton(
      value,
      R.color.recoverySurfaceRaised,
      R.color.recoverySurfaceFocused,
      R.color.recoveryText,
      action,
    ).apply {
      minWidth = dp(48)
      setPadding(dp(4), 0, dp(4), 0)
    }

  private fun actionButton(
    value: String,
    backgroundColor: Int,
    activeBackgroundColor: Int,
    textColor: Int,
    action: () -> Unit,
  ): Button = Button(this).apply {
    text = value
    isAllCaps = false
    textSize = 15f
    setTextColor(color(textColor))
    background = statefulRoundedSurface(
      restingColorResource = backgroundColor,
      activeColorResource = activeBackgroundColor,
      radiusDp = 12,
      strokeColorResource = R.color.recoveryBorder,
    )
    layoutParams = LinearLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT,
      ViewGroup.LayoutParams.WRAP_CONTENT,
    )
    minHeight = dp(48)
    minimumHeight = dp(48)
    filterTouchesWhenObscured = true
    isSaveEnabled = false
    setOnClickListener { action() }
  }

  private fun ViewGroup.addOwnedButton(
    button: Button,
    params: ViewGroup.LayoutParams? = null,
  ) {
    try {
      if (params == null) addView(button) else addView(button, params)
    } catch (failure: Throwable) {
      button.setOnClickListener(null)
      throw failure
    }
  }

  private fun roundedSurface(
    colorResource: Int,
    radiusDp: Int,
    strokeColorResource: Int? = null,
    strokeWidthDp: Int = 1,
  ): GradientDrawable =
    GradientDrawable().apply {
      shape = GradientDrawable.RECTANGLE
      cornerRadius = dp(radiusDp).toFloat()
      setColor(color(colorResource))
      if (strokeColorResource != null) setStroke(dp(strokeWidthDp), color(strokeColorResource))
    }

  private fun statefulRoundedSurface(
    restingColorResource: Int,
    activeColorResource: Int,
    radiusDp: Int,
    strokeColorResource: Int,
  ): StateListDrawable = StateListDrawable().apply {
    val active = roundedSurface(
      activeColorResource,
      radiusDp,
      R.color.recoveryPrimaryText,
      ACTIVE_OUTLINE_WIDTH_DP,
    )
    addState(intArrayOf(android.R.attr.state_pressed), active)
    addState(
      intArrayOf(android.R.attr.state_focused),
      roundedSurface(
        activeColorResource,
        radiusDp,
        R.color.recoveryPrimaryText,
        ACTIVE_OUTLINE_WIDTH_DP,
      ),
    )
    addState(
      intArrayOf(android.R.attr.state_hovered),
      roundedSurface(
        activeColorResource,
        radiusDp,
        R.color.recoveryPrimaryText,
        ACTIVE_OUTLINE_WIDTH_DP,
      ),
    )
    addState(
      intArrayOf(),
      roundedSurface(restingColorResource, radiusDp, strokeColorResource),
    )
  }

  private fun clearSensitiveViews() {
    activeRenderGeneration =
      if (activeRenderGeneration == Long.MAX_VALUE) 1L else activeRenderGeneration + 1L
    val root = sensitiveRoot
    sensitiveRoot = null
    secureScroll = null

    fun clear(view: View) {
      try {
        if (view is Button) view.setOnClickListener(null)
        if (view is RecoveryPhraseGridView) view.wipe()
        if (view is RecoveryPrivateInputView) view.wipe()
        if (view is RecoveryWordChoiceButton) view.wipe()
        if (view.tag === SECRET_VIEW_TAG && view is TextView) view.text = ""
      } catch (_: Throwable) {
        // Continue wiping the rest of the owned tree.
      }
      if (view is ViewGroup) {
        val childCount = try {
          view.childCount
        } catch (_: Throwable) {
          0
        }
        for (index in 0 until childCount) {
          try {
            clear(view.getChildAt(index))
          } catch (_: Throwable) {
            // One malformed child must not prevent cleanup of its siblings.
          }
        }
      }
    }
    if (root != null) {
      clear(root)
      try {
        root.removeAllViews()
      } catch (_: Throwable) {
        // References above are already invalidated and callbacks were cleared.
      }
    }
  }

  private fun weightedCell(): LinearLayout.LayoutParams =
    LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)

  private fun fullWidthCell(): LinearLayout.LayoutParams =
    LinearLayout.LayoutParams(
      ViewGroup.LayoutParams.MATCH_PARENT,
      ViewGroup.LayoutParams.WRAP_CONTENT,
    )

  private fun gridCell(): GridLayout.LayoutParams =
    GridLayout.LayoutParams().apply {
      width = 0
      height = ViewGroup.LayoutParams.WRAP_CONTENT
      columnSpec = GridLayout.spec(GridLayout.UNDEFINED, 1f)
      setMargins(dp(4), dp(4), dp(4), dp(4))
    }

  private fun space(sizeDp: Int): Space = Space(this).apply {
    layoutParams = LinearLayout.LayoutParams(dp(sizeDp), dp(sizeDp))
  }

  private fun color(resource: Int): Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
    getColor(resource)
  } else {
    @Suppress("DEPRECATION")
    resources.getColor(resource)
  }

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

  private fun isLargeFont(): Boolean =
    resources.configuration.fontScale >= LARGE_FONT_SCALE

  private fun View.excludeFromAutofill(hideDescendants: Boolean = false) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      importantForAutofill =
        if (hideDescendants) {
          View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        } else {
          View.IMPORTANT_FOR_AUTOFILL_NO
        }
    }
  }

  private fun View.excludeFromContentCapture(hideDescendants: Boolean = false) {
    RecoveryContentCapture.exclude(this, hideDescendants)
  }

  companion object {
    private const val EXTRA_MODE = "io.veil.mobile.recovery.MODE"
    private const val EXTRA_LEASE_ID = "io.veil.mobile.recovery.LEASE_ID"
    private const val EXTRA_RESULT_LEASE_ID = "io.veil.mobile.recovery.RESULT_LEASE_ID"
    private const val EXTRA_RESULT_OUTCOME = "io.veil.mobile.recovery.RESULT_OUTCOME"
    private const val INVALID_LEASE_ID = -1L
    private const val ROOT_HORIZONTAL_INSET_DP = 20
    private const val ISLAND_MAX_WIDTH_DP = 520
    private const val ADVANCING_ACTION_DEBOUNCE_MS = 400L
    private const val SUGGESTION_COLUMN_COUNT = 2
    private const val SUGGESTION_SLOT_COUNT = 4
    private const val LARGE_FONT_SCALE = 1.5f
    private const val ACTIVE_OUTLINE_WIDTH_DP = 2
    private val SECRET_VIEW_TAG = Any()

    fun intent(
      context: Context,
      mode: RecoveryMode,
      lease: NativeIdentitySetupCoordinator.Lease,
    ): Intent =
      Intent(context, RecoveryActivity::class.java).apply {
        putExtra(EXTRA_MODE, if (mode == RecoveryMode.CREATE) "create" else "restore")
        putExtra(EXTRA_LEASE_ID, lease.id)
        addFlags(Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS)
      }

    fun resultLeaseId(data: Intent?): Long? {
      if (data == null || !data.hasExtra(EXTRA_RESULT_LEASE_ID)) return null
      return try {
        data.getLongExtra(EXTRA_RESULT_LEASE_ID, INVALID_LEASE_ID)
      } catch (_: Throwable) {
        null
      }
    }

    fun resultOutcome(data: Intent?): NativeIdentitySetupOutcome? {
      if (data == null || !data.hasExtra(EXTRA_RESULT_OUTCOME)) return null
      return try {
        NativeIdentitySetupOutcome.fromBridge(data.getStringExtra(EXTRA_RESULT_OUTCOME))
      } catch (_: Throwable) {
        null
      }
    }
  }
}

private enum class TransactionUi {
  SETUP,
  COMMITTING,
  FAILED,
}

internal enum class NativeIdentitySetupOutcome(val bridgeValue: String) {
  COMMITTED("committed"),
  USER_CANCELLED("user_cancelled"),
  INTERRUPTED("interrupted");

  companion object {
    fun fromBridge(value: String?): NativeIdentitySetupOutcome? =
      entries.firstOrNull { outcome -> outcome.bridgeValue == value }
  }
}

@android.annotation.SuppressLint("ViewConstructor")
private class RecoveryIslandLayout(
  context: Context,
  maxWidthDp: Int,
) : LinearLayout(context) {
  private val maxWidthPx = (maxWidthDp * resources.displayMetrics.density).toInt()

  override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
    val widthMode = View.MeasureSpec.getMode(widthMeasureSpec)
    val widthSize = View.MeasureSpec.getSize(widthMeasureSpec)
    val cappedWidth = minOf(widthSize, maxWidthPx)
    val cappedWidthSpec = when (widthMode) {
      View.MeasureSpec.EXACTLY -> View.MeasureSpec.makeMeasureSpec(cappedWidth, View.MeasureSpec.EXACTLY)
      View.MeasureSpec.AT_MOST -> View.MeasureSpec.makeMeasureSpec(cappedWidth, View.MeasureSpec.AT_MOST)
      else -> View.MeasureSpec.makeMeasureSpec(maxWidthPx, View.MeasureSpec.AT_MOST)
    }
    super.onMeasure(cappedWidthSpec, heightMeasureSpec)
  }
}

private data class RecoverySafeInsets(
  val left: Int,
  val top: Int,
  val right: Int,
  val bottom: Int,
)

@android.annotation.TargetApi(Build.VERSION_CODES.P)
private object Api28Cutout {
  fun safeInsets(insets: WindowInsets): RecoverySafeInsets {
    val cutout = insets.displayCutout
    return RecoverySafeInsets(
      left = cutout?.safeInsetLeft ?: 0,
      top = cutout?.safeInsetTop ?: 0,
      right = cutout?.safeInsetRight ?: 0,
      bottom = cutout?.safeInsetBottom ?: 0,
    )
  }
}

@android.annotation.TargetApi(Build.VERSION_CODES.TIRAMISU)
private object Api33Back {
  fun register(activity: RecoveryActivity, action: () -> Unit): Any {
    val callback = android.window.OnBackInvokedCallback { action() }
    activity.onBackInvokedDispatcher.registerOnBackInvokedCallback(
      android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT,
      callback,
    )
    return callback
  }

  fun unregister(activity: RecoveryActivity, callback: Any) {
    activity.onBackInvokedDispatcher.unregisterOnBackInvokedCallback(
      callback as android.window.OnBackInvokedCallback,
    )
  }
}

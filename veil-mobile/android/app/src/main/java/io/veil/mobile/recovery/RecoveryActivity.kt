package io.veil.mobile.recovery

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
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
 * and only an empty RESULT_OK/RESULT_CANCELED leaves it. Recovery words never cross Intent,
 * Bundle, React Native, clipboard, autofill, accessibility, or the system IME.
 */
internal class RecoveryActivity : Activity(), NativeIdentitySetupCoordinator.Ceremony {
  private val terminal = AtomicBoolean(false)
  private val commitStarted = AtomicBoolean(false)
  private val foregroundGate = RecoveryForegroundGate()
  private var pendingMode: RecoveryMode? = null
  private var controller: RecoveryFlowController? = null
  private var dictionary: RecoveryWordDictionary? = null
  private var provisioner: NativeIdentityProvisioner? = null
  private var sensitiveRoot: ViewGroup? = null
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
      finishCancelled()
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
        finishCancelled()
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
      // Activity. The bridge receives only the cancelled terminal status.
      finishCancelled()
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
            finishCancelled()
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
      TransactionUi.COMMITTING -> {
        val root = newSecureRoot()
        root.addView(brandHeader())
        root.addView(space(24))
        renderCommitting(root)
        installSecureRoot(root)
      }
      TransactionUi.FAILED -> {
        val root = newSecureRoot()
        root.addView(brandHeader())
        root.addView(space(24))
        renderFailed(root)
        installSecureRoot(root)
      }
    }
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
    clearSensitiveViews()

    val root = newSecureRoot()
    root.addView(brandHeader())
    root.addView(space(24))

    when (flow.stage) {
      RecoveryStage.CREATE_REVIEW -> renderCreateReview(root, flow, words)
      RecoveryStage.CREATE_CHALLENGE -> renderCreateChallenge(root, flow, words)
      RecoveryStage.RESTORE_ENTRY -> renderRestoreEntry(root, flow, words)
      RecoveryStage.READY_TO_COMMIT -> renderReady(root, flow)
      RecoveryStage.COMMITTING -> renderCommitting(root)
      RecoveryStage.CLOSED -> renderFailed(root)
      RecoveryStage.COMMITTED -> Unit
    }

    installSecureRoot(root)
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
      finishCancelledTerminal()
      false
    }
  }

  private fun newSecureRoot(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    setPadding(dp(24), dp(24), dp(24), dp(40))
    setBackgroundColor(color(R.color.recoveryBackground))
    fitsSystemWindows = true
    excludeFromAutofill(hideDescendants = true)
    excludeFromContentCapture(hideDescendants = true)
    filterTouchesWhenObscured = true
  }

  private fun installSecureRoot(root: LinearLayout) {
    clearSensitiveViews()
    val scroll = ScrollView(this).apply {
      isFillViewport = true
      isSaveEnabled = false
      addView(
        root,
        ViewGroup.LayoutParams(
          ViewGroup.LayoutParams.MATCH_PARENT,
          ViewGroup.LayoutParams.WRAP_CONTENT,
        ),
      )
    }
    sensitiveRoot = root
    setContentView(scroll)
  }

  private fun renderCreateReview(
    root: LinearLayout,
    flow: RecoveryFlowController,
    words: RecoveryWordDictionary,
  ) {
    root.addView(titleText(getString(R.string.recovery_create_title)))
    root.addView(bodyText(getString(R.string.recovery_create_intro)))
    root.addView(space(18))
    root.addView(recoveryWordGrid(flow, words))
    root.addView(space(12))
    root.addView(privacyNotice())
    root.addView(space(24))
    root.addView(primaryButton(getString(R.string.recovery_continue)) {
      flow.continueFromCreateReview()
      renderCurrentUi()
    })
    root.addView(space(10))
    root.addView(secondaryButton(getString(R.string.recovery_cancel)) { finishCancelled() })
  }

  private fun renderCreateChallenge(
    root: LinearLayout,
    flow: RecoveryFlowController,
    words: RecoveryWordDictionary,
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
      importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
      excludeFromAutofill(hideDescendants = true)
      excludeFromContentCapture(hideDescendants = true)
    }
    val choices = flow.challengeChoices()
    try {
      for (index in choices) {
        secretChoices.addView(secretChoiceButton(words.word(index), index) { chosen ->
          flow.chooseChallengeWord(chosen)
          renderCurrentUi()
        })
        secretChoices.addView(space(10))
      }
    } finally {
      choices.fill(-1)
    }
    root.addView(secretChoices)
    root.addView(privacyNotice())
    root.addView(space(18))
    root.addView(secondaryButton(getString(R.string.recovery_cancel)) { finishCancelled() })
  }

  private fun renderRestoreEntry(
    root: LinearLayout,
    flow: RecoveryFlowController,
    words: RecoveryWordDictionary,
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
    root.addView(recoveryWordGrid(flow, words))
    root.addView(space(16))

    val secretInput = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(16), dp(14), dp(16), dp(14))
      background = roundedSurface(R.color.recoverySurfaceRaised, 14)
      importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
      excludeFromAutofill(hideDescendants = true)
      excludeFromContentCapture(hideDescendants = true)
    }
    secretInput.addView(eyebrowText(getString(R.string.recovery_private_input)))
    val inputChars = flow.inputCopy()
    try {
      secretInput.addView(RecoveryPrivateInputView(this, inputChars))
    } finally {
      inputChars.fill('\u0000')
    }
    secretInput.addView(space(10))

    val suggestions = flow.suggestions()
    try {
      if (suggestions.isNotEmpty()) {
        val suggestionRow = GridLayout(this).apply {
          columnCount = 2
          importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
        }
        for (index in suggestions) {
          val button = secretChoiceButton(words.word(index), index) { chosen ->
            flow.chooseImportWord(chosen)
            renderCurrentUi()
          }
          suggestionRow.addView(button, gridCell())
        }
        secretInput.addView(suggestionRow)
      }
    } finally {
      suggestions.fill(-1)
    }
    root.addView(secretInput)
    root.addView(space(14))
    root.addView(alphabetKeyboard(flow))
    root.addView(space(10))

    val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
    actions.addView(
      secondaryButton(getString(R.string.recovery_erase)) {
        flow.eraseInput()
        renderCurrentUi()
      },
      weightedCell(),
    )
    actions.addView(space(10))
    actions.addView(
      secondaryButton(getString(R.string.recovery_clear)) {
        while (flow.eraseInput()) Unit
        renderCurrentUi()
      },
      weightedCell(),
    )
    root.addView(actions)
    root.addView(space(12))
    root.addView(privacyNotice())
    root.addView(space(18))
    root.addView(secondaryButton(getString(R.string.recovery_cancel)) { finishCancelled() })
  }

  private fun renderReady(root: LinearLayout, flow: RecoveryFlowController) {
    root.addView(titleText(getString(R.string.recovery_ready_title)))
    root.addView(bodyText(getString(R.string.recovery_ready_body)))
    root.addView(space(28))
    root.addView(
      primaryButton(
        getString(
          if (flow.mode == RecoveryMode.CREATE) {
            R.string.recovery_commit_create
          } else {
            R.string.recovery_commit_restore
          },
        ),
      ) { beginCommit() },
    )
    root.addView(space(10))
    root.addView(secondaryButton(getString(R.string.recovery_cancel)) { finishCancelled() })
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
    root.addView(primaryButton(getString(R.string.recovery_close)) { finishCancelled() })
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
      finishCancelled()
      return
    }
    val flow = controller
    if (flow == null) {
      finishCancelled()
      return
    }
    when (flow.handleBack()) {
      RecoveryBackResult.UPDATED -> renderCurrentUi()
      RecoveryBackResult.CANCEL -> finishCancelled()
      RecoveryBackResult.BLOCKED -> Unit
    }
  }

  private fun finishCancelled() {
    if (transactionUi == TransactionUi.COMMITTING) {
      handleVisibilityLoss()
      return
    }
    finishCancelledTerminal()
  }

  private fun finishCancelledTerminal() {
    if (!terminal.compareAndSet(false, true)) return
    foregroundGate.markBackground()
    clearSensitiveViews()
    controller?.close()
    controller = null
    setTerminalResult(RESULT_CANCELED)
    finish()
  }

  private fun finishAlreadyProvisioned() {
    finishCommitted()
  }

  private fun finishCommitted() {
    if (!terminal.compareAndSet(false, true)) return
    foregroundGate.markBackground()
    clearSensitiveViews()
    setTerminalResult(RESULT_OK)
    finish()
  }

  private fun setTerminalResult(resultCode: Int) {
    val lease = setupLease
    if (lease == null) {
      setResult(resultCode)
    } else {
      setResult(
        resultCode,
        Intent().putExtra(EXTRA_RESULT_LEASE_ID, lease.id),
      )
    }
  }

  private fun handleVisibilityLoss() {
    foregroundGate.markBackground()
    clearSensitiveViews()
    if (transactionUi == TransactionUi.COMMITTING) return
    if (!isChangingConfigurations && !isFinishing && !terminal.get()) {
      finishCancelledTerminal()
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
    val row = LinearLayout(this).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER_VERTICAL
    }
    row.addView(
      PhaseShiftMarkView(this),
      LinearLayout.LayoutParams(dp(40), dp(40)),
    )
    row.addView(space(12))
    row.addView(eyebrowText(getString(R.string.recovery_brand)))
    return row
  }

  private fun recoveryWordGrid(
    flow: RecoveryFlowController,
    words: RecoveryWordDictionary,
  ): View {
    val indices = IntArray(flow.wordCount()) { position -> flow.wordIndex(position) }
    return try {
      RecoveryPhraseGridView(
        context = this,
        dictionary = words,
        sourceIndices = indices,
      ).apply {
        setPadding(dp(10), dp(10), dp(10), dp(10))
        tag = SECRET_VIEW_TAG
      }
    } finally {
      indices.fill(-1)
    }
  }

  private fun alphabetKeyboard(flow: RecoveryFlowController): View {
    val grid = GridLayout(this).apply {
      columnCount = if (resources.configuration.screenWidthDp >= 600) 8 else 5
      alignmentMode = GridLayout.ALIGN_BOUNDS
      useDefaultMargins = false
    }
    for (letter in 'A'..'Z') {
      val button = compactButton(letter.toString()) {
        flow.appendInput(letter.lowercaseChar())
        renderCurrentUi()
      }
      grid.addView(button, gridCell(minimumHeightDp = 48))
    }
    return grid
  }

  private fun titleText(value: String): TextView = TextView(this).apply {
    text = value
    setTextColor(color(R.color.recoveryText))
    textSize = 28f
    typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    setLineSpacing(0f, 1.08f)
  }

  private fun bodyText(value: String): TextView = TextView(this).apply {
    text = value
    setTextColor(color(R.color.recoveryTextMuted))
    textSize = 16f
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
    actionButton(value, R.color.recoveryPrimary, R.color.recoveryBackground, action)

  private fun secondaryButton(value: String, action: () -> Unit): Button =
    actionButton(value, R.color.recoverySurfaceRaised, R.color.recoveryText, action)

  private fun secretChoiceButton(
    value: String,
    wordIndex: Int,
    action: (Int) -> Unit,
  ): View = RecoveryWordChoiceButton(this, value, wordIndex, action).apply {
    tag = SECRET_VIEW_TAG
  }

  private fun compactButton(value: String, action: () -> Unit): Button =
    actionButton(value, R.color.recoverySurface, R.color.recoveryText, action).apply {
      minWidth = dp(48)
      setPadding(dp(4), 0, dp(4), 0)
    }

  private fun actionButton(
    value: String,
    backgroundColor: Int,
    textColor: Int,
    action: () -> Unit,
  ): Button = Button(this).apply {
    text = value
    isAllCaps = false
    textSize = 15f
    setTextColor(color(textColor))
    background = roundedSurface(backgroundColor, 12)
    minHeight = dp(48)
    minimumHeight = dp(48)
    filterTouchesWhenObscured = true
    isSaveEnabled = false
    setOnClickListener { action() }
  }

  private fun roundedSurface(colorResource: Int, radiusDp: Int): GradientDrawable =
    GradientDrawable().apply {
      shape = GradientDrawable.RECTANGLE
      cornerRadius = dp(radiusDp).toFloat()
      setColor(color(colorResource))
    }

  private fun clearSensitiveViews() {
    fun clear(view: View) {
      if (view is RecoveryPhraseGridView) view.wipe()
      if (view is RecoveryPrivateInputView) view.wipe()
      if (view is RecoveryWordChoiceButton) view.wipe()
      if (view.tag === SECRET_VIEW_TAG && view is TextView) view.text = ""
      if (view is ViewGroup) {
        for (index in 0 until view.childCount) clear(view.getChildAt(index))
      }
    }
    sensitiveRoot?.let(::clear)
    sensitiveRoot?.removeAllViews()
    sensitiveRoot = null
  }

  private fun weightedCell(): LinearLayout.LayoutParams =
    LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)

  private fun gridCell(minimumHeightDp: Int = 52): GridLayout.LayoutParams =
    GridLayout.LayoutParams().apply {
      width = 0
      height = dp(minimumHeightDp)
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
    private const val INVALID_LEASE_ID = -1L
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
      return data.getLongExtra(EXTRA_RESULT_LEASE_ID, INVALID_LEASE_ID)
    }
  }
}

private enum class TransactionUi {
  SETUP,
  COMMITTING,
  FAILED,
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

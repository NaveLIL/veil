package io.veil.mobile.recovery

import android.system.Os
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/** Real syscalls: run on each supported ABI on a disposable emulator only. */
@RunWith(AndroidJUnit4::class)
class AndroidIdentitySetupJournalInstrumentedTest {
  @Test
  fun freshJournalReadsAbsentAcrossProcessOwners() = withProbeDirectory { directory ->
    // Includes locking and fsync of the parent before returning absence.
    // The old x86 flag constants fail here on ARM64 with EINVAL.
    assertNull(NativeIdentitySetupJournal(directory).readOrNull())
    assertNull(NativeIdentitySetupJournal(directory).readOrNull())
  }

  @Test
  fun journalPublishesRecoversAndClearsOnlyAnExactTerminalReceipt() =
    withProbeDirectory { directory ->
      val first = NativeIdentitySetupJournal(directory)
      val prepared = first.begin(NativeIdentitySetupJournalMode.CREATE)
      val second = NativeIdentitySetupJournal(directory)
      assertEquals(prepared, second.readOrNull())
      assertThrows(NativeIdentitySetupJournalException::class.java) {
        second.clearTerminal(prepared)
      }
      val terminal = second.transition(
        prepared,
        NativeIdentitySetupJournalPhase.TERMINAL,
        NativeIdentitySetupJournalOutcome.INTERRUPTED,
      )
      assertEquals(terminal, NativeIdentitySetupJournal(directory).readOrNull())
      second.clearTerminal(terminal)
      assertNull(NativeIdentitySetupJournal(directory).readOrNull())
    }

  @Test
  fun symlinkLockCannotBeFollowedEvenToARegularFile() = withProbeDirectory { directory ->
    val target = File(directory, "probe-target")
    val bytes = byteArrayOf(1, 2, 3, 4)
    target.writeBytes(bytes)
    Os.symlink(target.absolutePath, File(directory, ".veil-identity-setup-journal.lock").absolutePath)
    assertThrows(NativeIdentitySetupJournalException::class.java) {
      NativeIdentitySetupJournal(directory).readOrNull()
    }
    assertArrayEquals(bytes, target.readBytes())
  }

  private fun withProbeDirectory(operation: (File) -> Unit) {
    val parent = InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir
    val directory = File(parent, ".veil-journal-probe-${UUID.randomUUID()}")
    check(directory.mkdir())
    try {
      operation(directory)
    } finally {
      val children = directory.listFiles() ?: error("cannot list journal probe")
      val allowed = setOf(
        ".veil-identity-setup-journal.lock",
        ".veil-identity-setup-journal.v1",
        ".veil-identity-setup-journal.v1.new",
        "probe-target",
      )
      check(children.all { it.name in allowed })
      // Unlink exact probe entries, including a symlink itself; never recurse.
      children.forEach { Os.remove(it.absolutePath) }
      Os.remove(directory.absolutePath)
    }
  }
}

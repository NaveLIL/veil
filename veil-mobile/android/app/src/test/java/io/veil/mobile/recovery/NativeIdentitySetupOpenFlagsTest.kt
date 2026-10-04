package io.veil.mobile.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NativeIdentitySetupOpenFlagsTest {
  @Test
  fun arm64DirectoryOpenRetainsDirectoryAndNoFollowWithoutDirectIo() {
    // Android NDK 27.1 aarch64-linux-android/asm/fcntl.h, not host Linux flags.
    val noFollow = 0x8000
    val directory = nativeIdentitySetupDirectoryFlag(noFollow)
    val flags = directory or noFollow or 0x80000
    assertEquals(0x4000, directory)
    assertEquals(0x8c000, flags)
    assertEquals(0, flags and 0x10000) // ARM64 O_DIRECT caused fresh journal open to fail.
    assertEquals(0, flags and 0x20000) // ARM64 O_LARGEFILE is not O_NOFOLLOW.
  }

  @Test
  fun x86DirectoryOpenRetainsItsOwnKernelFlagLayout() {
    // Android NDK 27.1 asm-generic/fcntl.h, included by x86_64 asm/fcntl.h.
    val noFollow = 0x20000
    val directory = nativeIdentitySetupDirectoryFlag(noFollow)
    assertEquals(0x10000, directory)
    assertEquals(0xb0000, directory or noFollow or 0x80000)
  }

  @Test
  fun unsupportedPlatformCannotProceedWithAssumedHostFlags() {
    for (unknown in listOf(0, 0x4000, 0x10000, 0x28000, -1)) {
      assertThrows(NativeIdentitySetupJournalException::class.java) {
        nativeIdentitySetupDirectoryFlag(unknown)
      }
    }
  }
}

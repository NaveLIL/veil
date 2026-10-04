import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.zip.*;

/** Verify the actual archive rather than trusting a directory next to it. */
class VerifyDesignBundle {
  static String sha(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
  public static void main(String[] args) throws Exception {
    try (ZipFile zip = new ZipFile(args[0])) {
      Set<String> names = new HashSet<>();
      Set<String> abis = new TreeSet<>();
      for (ZipEntry entry : Collections.list(zip.entries())) {
        String name = entry.getName();
        if (!names.add(name)) throw new Exception("Duplicate APK entry");
        if (name.startsWith("lib/")) {
          if (name.toLowerCase(Locale.ROOT).matches(".*(veil|sqlcipher|uniffi|jna).*")) throw new Exception("Account native library present: " + name);
          abis.add(name.split("/")[1]);
        }
      }
      if (!abis.equals(new TreeSet<>(List.of("arm64-v8a", "x86_64")))) throw new Exception("Unexpected APK ABIs");
      ZipEntry bundle = zip.getEntry("assets/index.android.bundle");
      if (bundle == null) throw new Exception("Offline bundle missing");
      byte[] actual = zip.getInputStream(bundle).readAllBytes();
      byte[] expected = Files.readAllBytes(Path.of(args[1]));
      if (!Arrays.equals(actual, expected)) throw new Exception("Packaged bundle does not match verified source-map bundle");
      System.out.println("{\"verified\":true,\"bundleSha256\":\"" + sha(actual) + "\",\"noAccountLibraries\":true,\"abis\":[\"arm64-v8a\",\"x86_64\"]}");
    }
  }
}

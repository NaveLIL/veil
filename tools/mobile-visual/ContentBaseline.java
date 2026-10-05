import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.imageio.ImageIO;

/** Fixture-only visual QA. The caller chooses an app-content region, excluding system bars. */
public final class ContentBaseline {
  private static BufferedImage read(String path) throws Exception {
    BufferedImage image = ImageIO.read(Path.of(path).toFile());
    if (image == null) throw new IllegalArgumentException("Unsupported image");
    return image;
  }
  public static void main(String[] args) throws Exception {
    if (args.length == 7 && args[0].equals("crop")) {
      BufferedImage source = read(args[1]);
      Path output = Path.of(args[2]);
      if (Files.exists(output)) throw new IllegalArgumentException("Baseline already exists");
      int x = Integer.parseInt(args[3]), y = Integer.parseInt(args[4]);
      int width = Integer.parseInt(args[5]), height = Integer.parseInt(args[6]);
      BufferedImage content = source.getSubimage(x, y, width, height);
      Files.createDirectories(output.toAbsolutePath().getParent());
      if (!ImageIO.write(content, "png", output.toFile())) throw new IllegalStateException("PNG unavailable");
      System.out.println("{\"width\":" + width + ",\"height\":" + height + "}");
    } else if (args.length == 3 && args[0].equals("compare")) {
      BufferedImage before = read(args[1]), after = read(args[2]);
      if (before.getWidth() != after.getWidth() || before.getHeight() != after.getHeight())
        throw new IllegalArgumentException("Compare the same app-content region and configuration");
      long changed = 0, sum = 0, pixels = (long) before.getWidth() * before.getHeight();
      int maximum = 0;
      for (int y = 0; y < before.getHeight(); y++) for (int x = 0; x < before.getWidth(); x++) {
        int a = before.getRGB(x, y), b = after.getRGB(x, y), delta = 0;
        for (int shift : new int[]{0, 8, 16, 24}) {
          int difference = Math.abs(((a >>> shift) & 255) - ((b >>> shift) & 255));
          delta = Math.max(delta, difference);
          sum += difference;
        }
        maximum = Math.max(maximum, delta);
        if (delta > 8) changed++;
      }
      // Diagnostic only: anti-aliasing, font/OS differences and motion need human review.
      System.out.println("{\"pixels\":" + pixels + ",\"changedBeyond8\":" + changed
        + ",\"meanChannelDifference\":" + (sum / (pixels * 4.0)) + ",\"maxChannelDifference\":" + maximum + "}");
    } else throw new IllegalArgumentException("crop input output x y width height | compare before after");
  }
}

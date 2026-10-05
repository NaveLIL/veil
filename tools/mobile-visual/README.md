# App-content visual baselines

`ContentBaseline.java` uses the existing JDK, with no app dependency. It crops a
caller-selected content region and provides diagnostic image differences.
System status/navigation bars should be excluded. Do not use it to bypass the
account application's capture policy; only isolated fixtures are captured.

```powershell
javac -d D:/tmp/veil-visual tools/mobile-visual/ContentBaseline.java
java -cp D:/tmp/veil-visual ContentBaseline crop fixture.png baseline.png 0 98 1080 2224
java -cp D:/tmp/veil-visual ContentBaseline compare baseline.png candidate.png
```

The coordinates above describe the recorded Samsung test configuration, not
product layout constants. Use the correct region for another configuration.
Never overwrite an existing baseline. Compare the same fixture, theme, font,
screen size and motion setting. Keep dynamic clock/message-time regions out of
the comparison when creating new fixtures. Difference metrics are diagnostic,
not an automatic pixel-perfect release gate.

The session archive contains a manifest with each fixture's source/APK revision,
region and hash. The final safe-area change requires fresh device captures;
earlier captures must not be relabeled as the final build.

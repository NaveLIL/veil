# Veil NSIS artwork

The Windows installer uses the existing Veil application icon together with a
brand backdrop generated specifically for the NSIS welcome, finish, and header
surfaces. The installer never downloads artwork or references remote images.

`veil-installer-art-source.png` is the retained high-resolution source. Run
`generate-installer-art.ps1` from PowerShell after changing the source or icon
to regenerate the exact 24-bit BMP assets required by NSIS. The PNG previews
are kept for quick visual review without launching the installer.

Generation prompt:

> Create a premium abstract background artwork for the Veil secure messenger
> Windows installer. Dark near-black navy base (#0D0E14), deep midnight blue
> layers, restrained lavender-violet (#A78BFA) phase-shift light, subtle cool
> cyan accents, elegant translucent diagonal veils and fine flowing
> encrypted-signal lines. High-end modern privacy software aesthetic, calm and
> trustworthy, cinematic depth, soft controlled glow, crisp but not busy.
> Composition must work when cropped into both a tall narrow 164:314 installer
> sidebar and a very wide 150:57 installer header: keep the central-left and
> upper-right areas visually interesting, preserve generous dark negative
> space. No logos, no icons, no text, no letters, no UI mockup, no people, no
> padlocks, no shields, no stock-tech clichés. Seamless polished product-brand
> artwork, 1536x1024 landscape master.

param(
  [string]$SourcePath = (Join-Path $PSScriptRoot 'veil-installer-art-source.png'),
  [string]$IconPath = (Join-Path $PSScriptRoot '..\icons\icon.png')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function New-InstallerBitmap {
  param(
    [System.Drawing.Image]$Source,
    [System.Drawing.Image]$Icon,
    [int]$Width,
    [int]$Height,
    [System.Drawing.RectangleF]$SourceCrop,
    [string]$BmpPath,
    [string]$PreviewPath,
    [scriptblock]$Decorate
  )

  $bitmap = [System.Drawing.Bitmap]::new(
    $Width,
    $Height,
    [System.Drawing.Imaging.PixelFormat]::Format24bppRgb
  )
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)

  try {
    $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceOver
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.DrawImage(
      $Source,
      [System.Drawing.Rectangle]::new(0, 0, $Width, $Height),
      $SourceCrop.X,
      $SourceCrop.Y,
      $SourceCrop.Width,
      $SourceCrop.Height,
      [System.Drawing.GraphicsUnit]::Pixel
    )

    & $Decorate $graphics $Icon

    $bitmap.Save($BmpPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
    $bitmap.Save($PreviewPath, [System.Drawing.Imaging.ImageFormat]::Png)
  }
  finally {
    $graphics.Dispose()
    $bitmap.Dispose()
  }
}

$source = [System.Drawing.Image]::FromFile((Resolve-Path -LiteralPath $SourcePath))
$icon = [System.Drawing.Image]::FromFile((Resolve-Path -LiteralPath $IconPath))

try {
  New-InstallerBitmap `
    -Source $source `
    -Icon $icon `
    -Width 164 `
    -Height 314 `
    -SourceCrop ([System.Drawing.RectangleF]::new(0, 0, 535, 1024)) `
    -BmpPath (Join-Path $PSScriptRoot 'sidebar.bmp') `
    -PreviewPath (Join-Path $PSScriptRoot 'sidebar-preview.png') `
    -Decorate {
      param($graphics, $brandIcon)

      $shade = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(72, 5, 7, 17))
      $brand = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(242, 245, 247, 255))
      $muted = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(205, 184, 190, 214))
      $titleFont = [System.Drawing.Font]::new('Segoe UI Semibold', 15, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
      $taglineFont = [System.Drawing.Font]::new('Segoe UI Semibold', 6.5, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)

      try {
        $graphics.FillRectangle($shade, 0, 0, 164, 314)
        $graphics.DrawImage($brandIcon, [System.Drawing.Rectangle]::new(51, 35, 62, 62))

        $titleFormat = [System.Drawing.StringFormat]::new()
        $titleFormat.Alignment = [System.Drawing.StringAlignment]::Center
        $graphics.DrawString('VEIL', $titleFont, $brand, [System.Drawing.RectangleF]::new(0, 107, 164, 24), $titleFormat)
        $graphics.DrawString('PRIVATE BY DESIGN', $taglineFont, $muted, [System.Drawing.RectangleF]::new(0, 282, 164, 14), $titleFormat)
        $titleFormat.Dispose()
      }
      finally {
        $shade.Dispose()
        $brand.Dispose()
        $muted.Dispose()
        $titleFont.Dispose()
        $taglineFont.Dispose()
      }
    }

  New-InstallerBitmap `
    -Source $source `
    -Icon $icon `
    -Width 150 `
    -Height 57 `
    -SourceCrop ([System.Drawing.RectangleF]::new(0, 248, 1536, 584)) `
    -BmpPath (Join-Path $PSScriptRoot 'header.bmp') `
    -PreviewPath (Join-Path $PSScriptRoot 'header-preview.png') `
    -Decorate {
      param($graphics, $brandIcon)

      $shade = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(40, 5, 7, 17))
      try {
        $graphics.FillRectangle($shade, 0, 0, 150, 57)
        $graphics.DrawImage($brandIcon, [System.Drawing.Rectangle]::new(108, 9, 38, 38))
      }
      finally {
        $shade.Dispose()
      }
    }
}
finally {
  $icon.Dispose()
  $source.Dispose()
}

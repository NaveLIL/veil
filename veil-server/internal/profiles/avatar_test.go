package profiles

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

func encodedAvatar(t *testing.T, format string, width, height int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: 180, A: 255})
		}
	}
	var output bytes.Buffer
	var err error
	if format == "png" {
		err = png.Encode(&output, img)
	} else {
		err = jpeg.Encode(&output, img, &jpeg.Options{Quality: 92})
	}
	if err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestNormalizeAvatarReencodesBoundedSquareJPEG(t *testing.T) {
	for _, test := range []struct{ format, contentType string }{{"png", "image/png"}, {"jpeg", "image/jpeg"}} {
		t.Run(test.format, func(t *testing.T) {
			asset, err := normalizeAvatar(encodedAvatar(t, test.format, 720, 480), test.contentType)
			if err != nil {
				t.Fatal(err)
			}
			if asset.ContentType != "image/jpeg" || asset.Width != 512 || asset.Height != 512 || len(asset.Data) > maxAvatarOutputBytes || len(asset.SHA256) != 32 {
				t.Fatalf("unexpected normalized asset: type=%s dims=%dx%d bytes=%d digest=%d", asset.ContentType, asset.Width, asset.Height, len(asset.Data), len(asset.SHA256))
			}
			config, format, err := image.DecodeConfig(bytes.NewReader(asset.Data))
			if err != nil || format != "jpeg" || config.Width != 512 || config.Height != 512 {
				t.Fatalf("invalid output: %s %#v %v", format, config, err)
			}
		})
	}
}

func TestNormalizeAvatarRejectsAmbiguousOrOversizedInputs(t *testing.T) {
	pngBytes := encodedAvatar(t, "png", 20, 20)
	jpegBytes := encodedAvatar(t, "jpeg", 20, 20)
	cases := []struct {
		name, contentType string
		data              []byte
	}{
		{"remote-type", "image/svg+xml", pngBytes},
		{"mime-mismatch", "image/jpeg", pngBytes},
		{"png-trailing", "image/png", append(append([]byte(nil), pngBytes...), 0)},
		{"apng", "image/png", append(append([]byte(nil), pngBytes[:20]...), append([]byte("acTL"), pngBytes[20:]...)...)},
		{"jpeg-trailing", "image/jpeg", append(append([]byte(nil), jpegBytes...), 0)},
		{"too-wide", "image/png", encodedAvatar(t, "png", maxAvatarDimension+1, 1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeAvatar(test.data, test.contentType); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

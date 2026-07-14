package profiles

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
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
			asset, err := normalizeAvatar(context.Background(), encodedAvatar(t, test.format, 720, 480), test.contentType)
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
		{"apng", "image/png", insertPNGChunk(t, pngBytes, "acTL", make([]byte, 8))},
		{"jpeg-trailing", "image/jpeg", append(append([]byte(nil), jpegBytes...), 0)},
		{"png-second-terminator", "image/png", append(append(append([]byte(nil), pngBytes...), []byte("polyglot")...), pngBytes[len(pngBytes)-12:]...)},
		{"jpeg-second-terminator", "image/jpeg", append(append(append([]byte(nil), jpegBytes...), []byte("polyglot")...), 0xff, 0xd9)},
		{"too-wide", "image/png", encodedAvatar(t, "png", maxAvatarDimension+1, 1)},
		{"jpeg-bomb-header", "image/jpeg", jpegWithDimensions(t, jpegBytes, 65535, 65535)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeAvatar(context.Background(), test.data, test.contentType); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestNormalizeAvatarCropsExtremeAspectRatiosBeforeResize(t *testing.T) {
	for _, dimensions := range [][2]int{{4096, 1}, {1, 4096}, {4096, 2}, {99, 4096}} {
		name := fmt.Sprintf("%dx%d", dimensions[0], dimensions[1])
		t.Run(name, func(t *testing.T) {
			asset, err := normalizeAvatar(
				context.Background(),
				encodedAvatar(t, "png", dimensions[0], dimensions[1]),
				"image/png",
			)
			if err != nil {
				t.Fatal(err)
			}
			config, format, err := image.DecodeConfig(bytes.NewReader(asset.Data))
			if err != nil || format != "jpeg" || config.Width != 512 || config.Height != 512 {
				t.Fatalf("unexpected normalized output: format=%s config=%#v err=%v", format, config, err)
			}
		})
	}
}

type boundedSolidImage struct {
	bounds image.Rectangle
	color  color.Color
}

func (img boundedSolidImage) ColorModel() color.Model { return color.NRGBAModel }
func (img boundedSolidImage) Bounds() image.Rectangle { return img.bounds }
func (img boundedSolidImage) At(int, int) color.Color { return img.color }

func TestNormalizeAvatarHandlesMaximumPixelBudgetWithOneDecoderSlot(t *testing.T) {
	var encoded bytes.Buffer
	input := boundedSolidImage{
		bounds: image.Rect(0, 0, maxAvatarDimension, maxAvatarDimension),
		color:  color.NRGBA{R: 71, G: 112, B: 151, A: 255},
	}
	if err := png.Encode(&encoded, input); err != nil {
		t.Fatal(err)
	}
	asset, err := normalizeAvatar(context.Background(), encoded.Bytes(), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	if asset.Width != avatarOutputSize || asset.Height != avatarOutputSize || len(asset.Data) > maxAvatarOutputBytes {
		t.Fatalf("maximum input escaped output budget: %dx%d bytes=%d", asset.Width, asset.Height, len(asset.Data))
	}
}

func TestNormalizeAvatarStripsMetadataAndFlattensAlpha(t *testing.T) {
	secret := []byte("GPS=51.0000,secret-profile-metadata")
	jpegInput := encodedAvatar(t, "jpeg", 32, 32)
	commentLength := len(secret) + 2
	withComment := append([]byte{0xff, 0xd8, 0xff, 0xfe, byte(commentLength >> 8), byte(commentLength)}, secret...)
	withComment = append(withComment, jpegInput[2:]...)
	asset, err := normalizeAvatar(context.Background(), withComment, "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(asset.Data, secret) {
		t.Fatal("normalized avatar retained JPEG metadata")
	}

	transparent := image.NewNRGBA(image.Rect(0, 0, 8, 8))
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, transparent); err != nil {
		t.Fatal(err)
	}
	asset, err = normalizeAvatar(context.Background(), encoded.Bytes(), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := jpeg.Decode(bytes.NewReader(asset.Data))
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, _ := decoded.At(256, 256).RGBA()
	if r>>8 < 12 || r>>8 > 24 || g>>8 < 30 || g>>8 > 46 || b>>8 < 47 || b>>8 > 65 {
		t.Fatalf("transparent pixels were not flattened to the Veil background: %d,%d,%d", r>>8, g>>8, b>>8)
	}
}

func TestNormalizeAvatarWaitIsContextAware(t *testing.T) {
	for range cap(avatarDecodeSlots) {
		avatarDecodeSlots <- struct{}{}
	}
	defer func() {
		for range cap(avatarDecodeSlots) {
			<-avatarDecodeSlots
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := normalizeAvatar(ctx, encodedAvatar(t, "png", 8, 8), "image/png")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("saturated decoder did not honor cancellation: %v", err)
	}
}

func FuzzNormalizeAvatar(f *testing.F) {
	seedPNG := fuzzSeedAvatar("png")
	seedJPEG := fuzzSeedAvatar("jpeg")
	f.Add(seedPNG, "image/png")
	f.Add(seedJPEG, "image/jpeg")
	f.Add([]byte("not-an-image"), "image/png")
	f.Fuzz(func(t *testing.T, input []byte, contentType string) {
		if len(input) > maxAvatarInputBytes+1 {
			t.Skip()
		}
		asset, err := normalizeAvatar(context.Background(), input, contentType)
		if err != nil {
			return
		}
		if asset.ContentType != "image/jpeg" || asset.Width != 512 || asset.Height != 512 || len(asset.Data) > maxAvatarOutputBytes {
			t.Fatalf("normalizer escaped output contract: %#v", asset)
		}
	})
}

func fuzzSeedAvatar(format string) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	var output bytes.Buffer
	if format == "png" {
		_ = png.Encode(&output, img)
	} else {
		_ = jpeg.Encode(&output, img, &jpeg.Options{Quality: 90})
	}
	return output.Bytes()
}

func insertPNGChunk(t *testing.T, input []byte, name string, data []byte) []byte {
	t.Helper()
	if len(name) != 4 || len(input) < 33 {
		t.Fatal("invalid PNG chunk fixture")
	}
	chunk := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(chunk[:4], uint32(len(data)))
	copy(chunk[4:8], name)
	copy(chunk[8:], data)
	binary.BigEndian.PutUint32(chunk[8+len(data):], crc32.ChecksumIEEE(chunk[4:8+len(data)]))
	output := append([]byte(nil), input[:33]...)
	output = append(output, chunk...)
	return append(output, input[33:]...)
}

func jpegWithDimensions(t *testing.T, input []byte, width, height uint16) []byte {
	t.Helper()
	output := append([]byte(nil), input...)
	for i := 2; i+9 < len(output); i++ {
		if output[i] == 0xff && (output[i+1] == 0xc0 || output[i+1] == 0xc2) {
			binary.BigEndian.PutUint16(output[i+5:i+7], height)
			binary.BigEndian.PutUint16(output[i+7:i+9], width)
			return output
		}
	}
	t.Fatal("JPEG fixture has no SOF marker")
	return nil
}

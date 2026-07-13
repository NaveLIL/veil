package profiles

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	_ "image/png"
	"strings"

	"github.com/disintegration/imaging"
)

const (
	maxAvatarInputBytes  = 2 * 1024 * 1024
	maxAvatarOutputBytes = 256 * 1024
	maxAvatarDimension   = 4096
	maxAvatarPixels      = 16 * 1024 * 1024
	avatarOutputSize     = 512
)

var (
	ErrInvalidAvatar  = errors.New("invalid avatar image")
	avatarDecodeSlots = make(chan struct{}, 2)
)

func normalizeAvatar(input []byte, declaredType string) (*AvatarAsset, error) {
	if len(input) == 0 || len(input) > maxAvatarInputBytes {
		return nil, ErrInvalidAvatar
	}
	format, ok := strictAvatarFormat(input, declaredType)
	if !ok {
		return nil, ErrInvalidAvatar
	}
	config, decodedFormat, err := image.DecodeConfig(bytes.NewReader(input))
	if err != nil || decodedFormat != format || config.Width < 1 || config.Height < 1 ||
		config.Width > maxAvatarDimension || config.Height > maxAvatarDimension ||
		config.Width > maxAvatarPixels/config.Height {
		return nil, ErrInvalidAvatar
	}

	avatarDecodeSlots <- struct{}{}
	defer func() { <-avatarDecodeSlots }()
	decoded, err := imaging.Decode(bytes.NewReader(input), imaging.AutoOrientation(true))
	if err != nil {
		return nil, ErrInvalidAvatar
	}
	resized := imaging.Fill(decoded, avatarOutputSize, avatarOutputSize, imaging.Center, imaging.Lanczos)
	flattened := image.NewRGBA(image.Rect(0, 0, avatarOutputSize, avatarOutputSize))
	draw.Draw(flattened, flattened.Bounds(), &image.Uniform{C: color.RGBA{R: 18, G: 38, B: 55, A: 255}}, image.Point{}, draw.Src)
	draw.Draw(flattened, flattened.Bounds(), resized, resized.Bounds().Min, draw.Over)

	var output []byte
	for quality := 90; quality >= 60; quality -= 5 {
		var encoded bytes.Buffer
		if err := jpeg.Encode(&encoded, flattened, &jpeg.Options{Quality: quality}); err != nil {
			return nil, ErrInvalidAvatar
		}
		if encoded.Len() <= maxAvatarOutputBytes {
			output = encoded.Bytes()
			break
		}
	}
	if len(output) == 0 {
		return nil, ErrInvalidAvatar
	}
	digest := sha256.Sum256(output)
	return &AvatarAsset{
		ContentType: "image/jpeg",
		SHA256:      digest[:],
		Width:       avatarOutputSize,
		Height:      avatarOutputSize,
		Data:        output,
	}, nil
}

func strictAvatarFormat(input []byte, declaredType string) (string, bool) {
	declaredType = strings.ToLower(strings.TrimSpace(declaredType))
	switch declaredType {
	case "image/png":
		pngSignature := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
		iend := []byte{0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82}
		if !bytes.HasPrefix(input, pngSignature) || !bytes.HasSuffix(input, iend) || bytes.Contains(input, []byte("acTL")) {
			return "", false
		}
		return "png", true
	case "image/jpeg":
		if len(input) < 4 || input[0] != 0xff || input[1] != 0xd8 || input[len(input)-2] != 0xff || input[len(input)-1] != 0xd9 {
			return "", false
		}
		return "jpeg", true
	default:
		return "", false
	}
}

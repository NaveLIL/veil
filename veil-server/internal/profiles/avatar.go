package profiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
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
	avatarDecodeSlots = make(chan struct{}, 1)
)

func normalizeAvatar(ctx context.Context, input []byte, declaredType string) (*AvatarAsset, error) {
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

	select {
	case avatarDecodeSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-avatarDecodeSlots }()
	decoded, err := imaging.Decode(bytes.NewReader(input), imaging.AutoOrientation(true))
	if err != nil {
		return nil, ErrInvalidAvatar
	}
	// Crop in source coordinates before resizing. imaging.Fill resizes first;
	// for a valid 4096x1 input that would create a multi-gigabyte intermediate.
	// Source-first square cropping keeps every allocation bounded by the already
	// validated 16 MP input and the fixed 512x512 output.
	bounds := decoded.Bounds()
	side := min(bounds.Dx(), bounds.Dy())
	left := bounds.Min.X + (bounds.Dx()-side)/2
	top := bounds.Min.Y + (bounds.Dy()-side)/2
	cropBounds := image.Rect(left, top, left+side, top+side)
	var cropped image.Image
	if subImage, ok := decoded.(interface {
		SubImage(image.Rectangle) image.Image
	}); ok {
		cropped = subImage.SubImage(cropBounds)
	} else {
		cropped = imaging.Crop(decoded, cropBounds)
	}
	resized := imaging.Resize(cropped, avatarOutputSize, avatarOutputSize, imaging.Lanczos)
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
		if !strictPNG(input) {
			return "", false
		}
		return "png", true
	case "image/jpeg":
		if !strictJPEG(input) {
			return "", false
		}
		return "jpeg", true
	default:
		return "", false
	}
}

func strictPNG(input []byte) bool {
	signature := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	if !bytes.HasPrefix(input, signature) {
		return false
	}
	offset := len(signature)
	seenIHDR := false
	for offset < len(input) {
		if len(input)-offset < 12 {
			return false
		}
		length := uint64(binary.BigEndian.Uint32(input[offset : offset+4]))
		if length > uint64(len(input)-offset-12) {
			return false
		}
		chunkEnd := offset + 12 + int(length)
		chunkType := input[offset+4 : offset+8]
		chunkDataEnd := offset + 8 + int(length)
		storedCRC := binary.BigEndian.Uint32(input[chunkDataEnd:chunkEnd])
		if crc32.ChecksumIEEE(input[offset+4:chunkDataEnd]) != storedCRC {
			return false
		}
		name := string(chunkType)
		if !seenIHDR {
			if name != "IHDR" || length != 13 {
				return false
			}
			seenIHDR = true
		} else if name == "IHDR" {
			return false
		}
		if name == "acTL" || name == "fcTL" || name == "fdAT" {
			return false
		}
		if name == "IEND" {
			return length == 0 && chunkEnd == len(input)
		}
		offset = chunkEnd
	}
	return false
}

func strictJPEG(input []byte) bool {
	if len(input) < 4 || input[0] != 0xff || input[1] != 0xd8 {
		return false
	}
	offset := 2
	inScan := false
	for offset < len(input) {
		var marker byte
		if inScan {
			for {
				if offset >= len(input) {
					return false
				}
				if input[offset] != 0xff {
					offset++
					continue
				}
				for offset < len(input) && input[offset] == 0xff {
					offset++
				}
				if offset >= len(input) {
					return false
				}
				marker = input[offset]
				offset++
				if marker == 0x00 || (marker >= 0xd0 && marker <= 0xd7) {
					continue
				}
				break
			}
			inScan = false
		} else {
			if input[offset] != 0xff {
				return false
			}
			for offset < len(input) && input[offset] == 0xff {
				offset++
			}
			if offset >= len(input) {
				return false
			}
			marker = input[offset]
			offset++
		}

		if marker == 0xd9 {
			return offset == len(input)
		}
		if marker == 0xd8 || marker == 0x00 || (marker >= 0xd0 && marker <= 0xd7) {
			return false
		}
		if marker == 0x01 { // TEM is the only standalone non-entropy marker.
			continue
		}
		if len(input)-offset < 2 {
			return false
		}
		segmentLength := int(binary.BigEndian.Uint16(input[offset : offset+2]))
		if segmentLength < 2 || segmentLength > len(input)-offset {
			return false
		}
		offset += segmentLength
		if marker == 0xda {
			inScan = true
		}
	}
	return false
}

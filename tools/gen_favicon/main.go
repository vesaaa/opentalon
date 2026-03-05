package main

import (
	"image"
	"image/png"
	"log"
	"os"

	_ "image/jpeg"
	_ "image/png"
)

// 这个小工具从 webui/web/logo-opentalon-favicon-src.png 生成一个 64x64 的正方形 favicon.png：
// - 先在源图上做一次「中心裁剪」得到正方形区域（避免左右空白太多）
// - 再按原始宽高比等比缩放到 64x64 画布中
// - 画布为正方形，可以是透明或有背景色，取决于源图
func main() {
	const (
		inputPath  = "webui/web/assets/logo-opentalon-favicon-src.png"
		outputPath = "webui/web/favicon.png"
		size       = 64
		marginFrac = 0.02 // 极小边距，让图标尽量贴近四边
	)

	in, err := os.Open(inputPath)
	if err != nil {
		log.Fatalf("open input: %v", err)
	}
	defer in.Close()

	srcOrig, _, err := image.Decode(in)
	if err != nil {
		log.Fatalf("decode input: %v", err)
	}

	// 先把接近纯白的背景抠成透明
	b := srcOrig.Bounds()
	src := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := srcOrig.At(x, y).RGBA()
			rr := uint8(r >> 8)
			gg := uint8(g >> 8)
			bb := uint8(bl >> 8)
			// 只有真正的纯白像素才视为背景，其余全部保留（包括发光边缘）
			if a != 0 && rr == 255 && gg == 255 && bb == 255 {
				src.Set(x, y, image.Transparent)
			} else {
				src.Set(x, y, srcOrig.At(x, y))
			}
		}
	}

	b = src.Bounds()
	sw := b.Dx()
	sh := b.Dy()
	if sw == 0 || sh == 0 {
		log.Fatalf("invalid source size %dx%d", sw, sh)
	}

	// 这个源图已经是你裁好的 416x416 正方形，我们只需要去掉白底即可，
	// 不再额外裁剪，直接整体缩放。
	cropRect := b
	sub := src.SubImage(cropRect)

	// 目标画布：正方形、透明
	dst := image.NewRGBA(image.Rect(0, 0, size, size))

	// 计算缩放后大小（按短边限制，并预留 margin）
	maxInside := float64(size) * (1.0 - 2*marginFrac)
	scale := maxInside / float64(cropRect.Dx())
	dw := int(float64(cropRect.Dx()) * scale)
	dh := dw
	if dw <= 0 {
		dw = 1
	}
	if dh <= 0 {
		dh = 1
	}

	offX := (size - dw) / 2
	offY := (size - dh) / 2

	// 最近邻缩放：把中心裁剪后的正方形源图等比缩放到目标区域
	for y := 0; y < dh; y++ {
		for x := 0; x < dw; x++ {
			// 映射到源坐标（注意用 float 计算，保持等比）
			sx := int(float64(x) * float64(cropRect.Dx()) / float64(dw))
			sy := int(float64(y) * float64(cropRect.Dy()) / float64(dh))
			if sx >= cropRect.Dx() {
				sx = cropRect.Dx() - 1
			}
			if sy >= cropRect.Dy() {
				sy = cropRect.Dy() - 1
			}
			c := sub.At(sourceMinX(sub)+sx, sourceMinY(sub)+sy)
			dst.Set(offX+x, offY+y, c)
		}
	}

	out, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("create output: %v", err)
	}
	defer out.Close()

	if err := png.Encode(out, dst); err != nil {
		log.Fatalf("encode output: %v", err)
	}

	log.Printf("generated square favicon at %s (%dx%d)", outputPath, size, size)
}

func sourceMinX(img image.Image) int { return img.Bounds().Min.X }
func sourceMinY(img image.Image) int { return img.Bounds().Min.Y }



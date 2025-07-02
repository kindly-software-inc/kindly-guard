#!/bin/bash
# Convert SVG icons to platform-specific formats
# Requires: imagemagick, icotool

# Create output directories
mkdir -p win mac linux

# Function to convert SVG to multiple sizes
convert_icon() {
    local svg_file="$1"
    local base_name=$(basename "$svg_file" .svg)
    
    # Windows ICO (16x16, 32x32, 48x48, 256x256)
    convert "$svg_file" -resize 16x16 "temp-16.png"
    convert "$svg_file" -resize 32x32 "temp-32.png"
    convert "$svg_file" -resize 48x48 "temp-48.png"
    convert "$svg_file" -resize 256x256 "temp-256.png"
    
    # Create ICO file
    icotool -c -o "win/${base_name}.ico" temp-16.png temp-32.png temp-48.png temp-256.png
    rm temp-*.png
    
    # macOS PNG (16x16, 32x32, 64x64, 128x128, 256x256, 512x512)
    for size in 16 32 64 128 256 512; do
        convert "$svg_file" -resize ${size}x${size} "mac/${base_name}-${size}x${size}.png"
        # Create @2x versions for Retina displays
        if [ $size -le 256 ]; then
            let "size2x = size * 2"
            convert "$svg_file" -resize ${size2x}x${size2x} "mac/${base_name}-${size}x${size}@2x.png"
        fi
    done
    
    # Linux PNG (standard sizes)
    for size in 16 22 24 32 48 64 128 256; do
        convert "$svg_file" -resize ${size}x${size} "linux/${base_name}-${size}x${size}.png"
    done
}

# Convert all tray icons
for svg in tray-*.svg; do
    if [ -f "$svg" ]; then
        echo "Converting $svg..."
        convert_icon "$svg"
    fi
done

echo "Icon conversion complete!"
echo "Note: Install imagemagick and icotool if not already installed:"
echo "  Ubuntu/Debian: sudo apt-get install imagemagick icoutils"
echo "  macOS: brew install imagemagick icoutils"
echo "  Windows: Use WSL or install ImageMagick for Windows"
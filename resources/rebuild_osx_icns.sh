#!/bin/bash

mkdir Rekall.iconset
sips -z 16 16 Rekall.png --out Rekall.iconset/icon_16x16.png
sips -z 32 32 Rekall.png --out Rekall.iconset/icon_16x16@x2.png
sips -z 32 32 Rekall.png --out Rekall.iconset/icon_32x32.png
sips -z 64 64 Rekall.png --out Rekall.iconset/icon_32x32@x2.png
sips -z 64 64  Rekall.png --out Rekall.iconset/icon_64x64.png
sips -z 128 128 Rekall.png --out Rekall.iconset/icon_64x64@x2.png
sips -z 128 128 Rekall.png --out Rekall.iconset/icon_128x128.png
sips -z 256 256 Rekall.png --out Rekall.iconset/icon_128x128@x2.png
sips -z 256 256 Rekall.png --out Rekall.iconset/icon_256x256.png
sips -z 512 512 Rekall.png --out Rekall.iconset/icon_256x256@x2.png

iconutil -c icns Rekall.iconset


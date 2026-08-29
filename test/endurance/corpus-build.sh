#!/usr/bin/env bash
#
# Builds the soak corpus. Runs inside the corpus image, which carries the
# toolchain ImageMagick and the policy the server image ships.
#
# The corpus has four parts:
#
#   govdocs1     real world files from digitalcorpora, mixed types. Most of
#                them are not images: PDF, PostScript, Office, Flash, text.
#   commons      real images in the formats govdocs1 is thin on: PNG, TIFF,
#                WebP, SVG, animated GIF.
#   derived      re-encodings of the real images, one per format and feature.
#   generated    the hostile set: truncated, empty, mislabelled, and oversized.
#
# Every step writes a marker, so a second run adds only what is missing.
#
# The last step classifies each file. It reads the file from stdin, which is
# what the module does: a fetched source reaches ImageMagick as a blob, with no
# filename to read a format from. A file this image refuses is a file the
# module refuses.
#
# Copyright 2026 Jeremy Collins
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

OUT=/corpus
FILES="$OUT/files"
WORK="$OUT/work"
MANIFEST="$OUT/manifest.tsv"

GOVDOCS=${GOVDOCS:-4}
COMMONS=${COMMONS:-600}
DERIVE=${DERIVE:-900}
MAX_BYTES=${MAX_BYTES:-6291456}
RATE=${RATE:-1}
UA=${UA:-"mod_dims-soak/1.0 (https://github.com/beetlebugorg/mod_dims)"}

GOVDOCS_BASE=https://digitalcorpora.s3.amazonaws.com/corpora/files/govdocs1/zipfiles
COMMONS_API=https://commons.wikimedia.org/w/api.php

# A file larger than this decodes to more pixels than a soak wants to spend
# time on. The classifier marks it "either" rather than dropping it.
LARGE_BYTES=4194304
LARGE_PIXELS=40000000
LARGE_FRAMES=20

# A side this long survives a decode and then overflows a later operation, and
# a rotate or a thumbnail of it may fail on the dimension rather than the area.
LARGE_SIDE=20000

mkdir -p "$FILES" "$WORK"

log() { printf '\n=== %s ===\n' "$*" >&2; }
note() { printf '    %s\n' "$*" >&2; }

# -- govdocs1
#
# One archive holds a thousand files. The numbers are spread across the
# thousand archives rather than taken in order, so a small corpus still draws
# from the whole set.

fetch_govdocs() {
    local i number zip

    for (( i = 0; i < GOVDOCS; i++ )); do
        number=$(printf '%03d' $(( (i * 97) % 1000 )))
        [ -e "$OUT/.govdocs.$number" ] && continue

        zip="$WORK/$number.zip"
        note "govdocs1 $number.zip"
        if ! curl -fL --retry 3 --retry-delay 5 -C - -A "$UA" \
                --connect-timeout 30 --max-time 3600 \
                -o "$zip" "$GOVDOCS_BASE/$number.zip"; then
            note "govdocs1 $number.zip did not download, skipping"
            rm -f "$zip"
            continue
        fi

        # -j drops the directory names, -o overwrites. The names inside are
        # already unique across the whole corpus.
        unzip -qq -o -j "$zip" -d "$FILES" || note "unzip reported an error, keeping what it wrote"
        rm -f "$zip"
        : > "$OUT/.govdocs.$number"
    done
}

# -- Wikimedia Commons
#
# govdocs1 holds about ninety JPEG and twenty GIF per archive, one PNG, and no
# TIFF, WebP, or SVG. This step adds real files in those formats. A real file
# holds header values a re-encoding does not produce.
#
# One request per second, and a descriptive user agent, which is what the API
# asks for.

commons_page() { # mime, limit, offset
    curl -fsS --max-time 60 -A "$UA" --get \
        --data-urlencode "gsrsearch=filemime:$1" \
        --data-urlencode "gsrlimit=$2" \
        --data-urlencode "gsroffset=$3" \
        "$COMMONS_API?action=query&format=json&formatversion=2&generator=search&gsrnamespace=6&prop=imageinfo&iiprop=url|mime|size" \
    | sed 's/{"pageid":/\n{"pageid":/g'
}

fetch_commons() {
    local mimes=(image/png image/tiff image/webp image/svg+xml image/gif image/jpeg)
    local per offset mime record url size bytes ext name got total

    [ -e "$OUT/.commons" ] && return 0
    [ "$COMMONS" -gt 0 ] || { : > "$OUT/.commons"; return 0; }

    per=$(( COMMONS / ${#mimes[@]} + 1 ))
    total=0

    for mime in "${mimes[@]}"; do
        got=0
        offset=0
        while [ "$got" -lt "$per" ] && [ "$offset" -lt 4000 ]; do
            while IFS= read -r record; do
                # The text before the first record holds no fields, and a grep
                # that matches nothing fails the pipeline under pipefail.
                case "$record" in {\"pageid\":*) ;; *) continue ;; esac
                size=$(printf '%s' "$record" | grep -o '"size":[0-9]*' | head -1 | cut -d: -f2 || true)
                url=$(printf '%s' "$record" | grep -o '"url":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
                [ -n "$url" ] || continue
                [ -n "$size" ] || continue
                [ "$size" -gt 2048 ] && [ "$size" -le "$MAX_BYTES" ] || continue

                # The API appends its own tracking query. Drop it.
                url=${url%%\?*}
                ext=$(printf '%s' "${url##*.}" | tr 'A-Z' 'a-z')
                case "$ext" in
                    jpg|jpeg|png|gif|tif|tiff|webp|svg) ;;
                    *) continue ;;
                esac

                name="commons-$(printf '%s' "$url" | sha1sum | cut -c1-16).$ext"
                [ -e "$FILES/$name" ] && continue

                if curl -fsSL --max-time 120 --retry 2 --retry-delay 5 \
                        -A "$UA" -o "$FILES/$name" "$url"; then
                    bytes=$(stat -c %s "$FILES/$name")
                    if [ "$bytes" -lt 64 ]; then rm -f "$FILES/$name"; continue; fi
                    got=$(( got + 1 ))
                    total=$(( total + 1 ))
                else
                    rm -f "$FILES/$name"
                fi

                sleep "$RATE"
                [ "$got" -ge "$per" ] && break
            done < <(commons_page "$mime" 50 "$offset")

            offset=$(( offset + 50 ))
            sleep "$RATE"
        done
        note "$mime: $got"
    done

    note "commons total $total"
    : > "$OUT/.commons"
}

# -- Derived variants
#
# One recipe per format and per feature the module has to read: the colour
# spaces, the bit depths, the alpha channel, the interlacing, and the frame
# count. Each variant is a distinct file with distinct bytes and a distinct
# size.

RECIPES=(
    "tiff:tiff:-compress None"
    "tifflzw:tiff:-compress LZW"
    "tiffzip:tiff:-compress Zip"
    "webp:webp:-quality 80"
    "webpll:webp:-define webp:lossless=true"
    "png8:png:-depth 8 -type Palette"
    "png16:png:-depth 16"
    "pngalpha:png:-alpha set -channel A -evaluate set 60%"
    "pngint:png:-interlace PNG"
    "jpgprog:jpg:-interlace Plane -quality 82"
    "jpgcmyk:jpg:-colorspace CMYK -quality 88"
    "jpggray:jpg:-colorspace Gray -quality 75"
    "jpglow:jpg:-quality 12"
    "bmp:bmp:-type TrueColor"
    "gifpal:gif:-colors 64"
    "pnm:pnm:-compress None"
    "exifrot:jpg:-orient RightTop -quality 85"
)

derive() {
    local sources=() source recipe name label ext opts width count i

    [ -e "$OUT/.derive" ] && return 0
    [ "$DERIVE" -gt 0 ] || { : > "$OUT/.derive"; return 0; }

    # Sources for the variants: the real raster images already downloaded.
    while IFS= read -r source; do
        sources+=("$source")
    done < <(find "$FILES" -maxdepth 1 -type f \
                \( -name '*.jpg' -o -name '*.jpeg' -o -name '*.png' -o -name '*.gif' \) \
                -size +8k -size -3M | sort | head -400)

    if [ ${#sources[@]} -eq 0 ]; then
        note "no raster source to derive from"
        : > "$OUT/.derive"
        return 0
    fi

    count=0
    for (( i = 0; i < DERIVE; i++ )); do
        source=${sources[$(( i % ${#sources[@]} ))]}
        recipe=${RECIPES[$(( (i / ${#sources[@]} + i) % ${#RECIPES[@]} ))]}
        label=${recipe%%:*}
        ext=$(printf '%s' "$recipe" | cut -d: -f2)
        opts=$(printf '%s' "$recipe" | cut -d: -f3-)
        # Widths spread across the range a request asks for, so a variant is
        # sometimes smaller than the resize and sometimes larger.
        width=$(( 64 + (i * 37) % 1600 ))
        name="derived-$(printf '%05d' "$i")-$label.$ext"

        [ -e "$FILES/$name" ] && continue

        # shellcheck disable=SC2086
        if timeout 60 magick -limit memory 256MiB -limit map 512MiB \
                "$source[0]" -resize "${width}x${width}>" $opts "$FILES/$name" 2>/dev/null; then
            count=$(( count + 1 ))
        else
            rm -f "$FILES/$name"
        fi
    done

    note "derived $count"
    : > "$OUT/.derive"
}

# -- The generated set
#
# The inputs a production service receives by accident and on purpose: an empty
# body, a truncated stream, a file with the wrong extension, and an image whose
# header declares more pixels than the container has memory for.

first_of() { # extension -> a real file with that extension
    find "$FILES" -maxdepth 1 -type f -name "*.$1" -size +20k -size -2M | sort | head -1
}

corrupt_at() { # source, target, fraction of the file to keep intact
    local source=$1 target=$2 fraction=$3 size at
    size=$(stat -c %s "$source")
    at=$(( size * fraction / 100 ))
    # cp keeps the source mode, and a govdocs1 file arrives read only, so an
    # existing target has to go before cp can write one.
    rm -f "$target"
    cp "$source" "$target"
    chmod u+w "$target"
    printf '\xde\xad\xbe\xef' | dd of="$target" bs=1 seek="$at" conv=notrunc status=none
}

generate() {
    local jpeg png gif f

    [ -e "$OUT/.generated" ] && return 0

    # A file left by an interrupted run may be read only, and a redirection
    # cannot open one for writing.
    rm -f "$FILES"/gen-* 2>/dev/null || true

    jpeg=$(first_of jpg); [ -n "$jpeg" ] || jpeg=$(first_of jpeg)
    png=$(first_of png)
    gif=$(first_of gif)

    # A source for the ones that need a real image behind them. Draw one when
    # the corpus has none.
    if [ -z "$jpeg" ]; then
        jpeg="$WORK/seed.jpg"
        magick -size 640x480 gradient:navy-orange -quality 85 "$jpeg"
    fi
    if [ -z "$png" ]; then
        png="$WORK/seed.png"
        magick -size 640x480 plasma:fractal "$png"
    fi
    if [ -z "$gif" ]; then
        gif="$WORK/seed.gif"
        magick -size 320x240 plasma:fractal -colors 128 "$gif"
    fi

    # Empty, or close to it.
    : > "$FILES/gen-empty.jpg"
    printf '\xff' > "$FILES/gen-onebyte.png"
    printf '\xff\xd8' > "$FILES/gen-jpeg-header-only.jpg"
    printf '\x89PNG\r\n\x1a\n' > "$FILES/gen-png-header-only.png"
    head -c 4096 /dev/zero > "$FILES/gen-zeros.png"
    head -c 4096 /dev/urandom > "$FILES/gen-random.jpg"

    # Cut short. The header declares a stream that the file does not hold.
    head -c $(( $(stat -c %s "$jpeg") * 40 / 100 )) "$jpeg" > "$FILES/gen-truncated.jpg"
    head -c $(( $(stat -c %s "$png") * 40 / 100 )) "$png" > "$FILES/gen-truncated.png"
    head -c $(( $(stat -c %s "$gif") * 40 / 100 )) "$gif" > "$FILES/gen-truncated.gif"

    # Intact header, damaged payload. The decoder gets far enough to allocate.
    corrupt_at "$jpeg" "$FILES/gen-corrupt-scan.jpg" 60
    corrupt_at "$png" "$FILES/gen-corrupt-idat.png" 60
    corrupt_at "$gif" "$FILES/gen-corrupt-lzw.gif" 60

    # Not an image, under an image extension.
    printf 'this file is text, and the name says jpeg\n' > "$FILES/gen-text.jpg"
    printf '<html><head><title>not an image</title></head><body>404</body></html>\n' > "$FILES/gen-html.png"
    printf '#!/bin/sh\necho not an image\n' > "$FILES/gen-script.gif"
    head -c 65536 /bin/true > "$FILES/gen-elf.jpg" 2>/dev/null || printf '\x7fELF' > "$FILES/gen-elf.jpg"

    # Small on disk, enormous once decoded.
    magick -size 8000x8000 xc:'#336699' -define png:compression-level=9 "$FILES/gen-huge-square.png"
    magick -size 30000x8 gradient:red-blue "$FILES/gen-huge-wide.png"
    magick -size 8x30000 gradient:red-blue "$FILES/gen-huge-tall.png"
    magick -size 1x1 xc:white "$FILES/gen-one-pixel.png"

    # Many frames. The default returns a multi-frame source unchanged, and the
    # transform setting runs every command over each frame.
    magick -delay 2 -size 64x64 xc:red xc:green xc:blue xc:yellow \
        -write mpr:cycle +delete \
        \( mpr:cycle mpr:cycle mpr:cycle mpr:cycle mpr:cycle mpr:cycle \) \
        "$FILES/gen-frames.gif"

    # Metadata far larger than the pixels.
    magick "$jpeg" -resize 64x64 -set comment "$(head -c 60000 /dev/urandom | base64 | tr -d '\n')" \
        "$FILES/gen-fat-metadata.jpg"

    # SVG. The renderer reads a local file named by an href, so the module
    # refuses an SVG that points at an external resource before it gets there.
    cat > "$FILES/gen-svg-clean.svg" <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300" viewBox="0 0 400 300">
  <rect width="400" height="300" fill="#1d3557"/>
  <circle cx="200" cy="150" r="90" fill="#f1faee"/>
  <path d="M40 260 L200 40 L360 260 Z" fill="none" stroke="#e63946" stroke-width="8"/>
</svg>
SVG
    cat > "$FILES/gen-svg-external.svg" <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="400" height="300">
  <image xlink:href="http://origin:8080/gen-svg-clean.svg" x="0" y="0" width="400" height="300"/>
</svg>
SVG
    cat > "$FILES/gen-svg-local.svg" <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="200" height="200">
  <image xlink:href="/etc/passwd" x="0" y="0" width="200" height="200"/>
</svg>
SVG
    cat > "$FILES/gen-svg-entity.svg" <<'SVG'
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&d;</text>
</svg>
SVG
    cat > "$FILES/gen-svg-huge.svg" <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="60000" height="60000">
  <rect width="60000" height="60000" fill="#222222"/>
</svg>
SVG

    for f in "$FILES"/gen-*; do
        [ -s "$f" ] || continue
    done

    note "generated $(find "$FILES" -maxdepth 1 -name 'gen-*' | wc -l)"
    : > "$OUT/.generated"
}

# -- Classify
#
# Read each file the way the module reads it: from a stream, with no filename
# to read a format from. A file this step refuses is a file the module refuses,
# so the class comes from a decode, not from the extension.
#
#   image    the toolchain decodes it, so a valid request must return an image
#   reject   the toolchain refuses it, so every request for it must fail
#   either   large, multi-frame, or an SVG with a reference: both results are
#            allowed, and only a crash or a hang is a failure

classify() {
    local file name bytes info format width height frames pixels class

    : > "$MANIFEST"
    printf '# name\tformat\tbytes\tclass\n' >> "$MANIFEST"

    while IFS= read -r file; do
        name=$(basename "$file")
        bytes=$(stat -c %s "$file")

        # Drop what is too large to be worth serving thousands of times.
        if [ "$bytes" -gt "$MAX_BYTES" ]; then
            rm -f "$file"
            continue
        fi

        # The limits go after the subcommand. Before it, magick reads
        # "identify" as a file name.
        # A compressed container. identify writes stdin to a temporary file
        # and unwraps it; the module reads the source as a blob and does not.
        # So the module refuses these whatever identify reports.
        case $(head -c 4 "$file" | od -An -tx1 | tr -d ' \n') in
            1f8b*|425a68*|fd377a58|504b0304)
                printf '%s\t-\t%s\treject\n' "$name" "$bytes" >> "$MANIFEST"
                continue
                ;;
        esac

        info=$(timeout 25 magick identify -limit memory 512MiB -limit map 1GiB \
                -format '%m %w %h %n\n' - < "$file" 2>/dev/null | head -1 || true)

        if [ -z "$info" ]; then
            # XML that is not a clean SVG. identify reads its input from a file
            # and the module reads a blob, and the SVG coder does not always
            # reach the same answer from both, so neither result is required.
            # HTML is not included: the module has to refuse it.
            if head -c 512 "$file" | grep -qiE '^[[:space:]]*(<\?xml|<svg)'; then
                printf '%s\t-\t%s\teither\n' "$name" "$bytes" >> "$MANIFEST"
            else
                printf '%s\t-\t%s\treject\n' "$name" "$bytes" >> "$MANIFEST"
            fi
            continue
        fi

        format=$(printf '%s' "$info" | cut -d' ' -f1)
        width=$(printf '%s' "$info" | cut -d' ' -f2)
        height=$(printf '%s' "$info" | cut -d' ' -f3)
        frames=$(printf '%s' "$info" | cut -d' ' -f4)
        [ "$width" -gt 0 ] 2>/dev/null || width=0
        [ "$height" -gt 0 ] 2>/dev/null || height=0
        [ "$frames" -gt 0 ] 2>/dev/null || frames=1
        pixels=$(( width * height ))

        class=image
        if [ "$pixels" -gt "$LARGE_PIXELS" ] || [ "$frames" -gt "$LARGE_FRAMES" ] ||
                [ "$bytes" -gt "$LARGE_BYTES" ] ||
                [ "$width" -gt "$LARGE_SIDE" ] || [ "$height" -gt "$LARGE_SIDE" ]; then
            class=either
        fi

        # The SVG guard runs before the renderer, so it refuses documents the
        # decoder reads without complaint: an external or local reference, and
        # a document type declaration.
        case "$format" in
            SVG|MSVG)
                if grep -qiE 'href[[:space:]]*=|<!DOCTYPE|<!ENTITY' "$file"; then
                    class=either
                fi
                ;;
        esac

        printf '%s\t%s\t%s\t%s\n' "$name" "$format" "$bytes" "$class" >> "$MANIFEST"
    done < <(find "$FILES" -maxdepth 1 -type f | sort)
}

log "govdocs1"
fetch_govdocs
log "wikimedia commons"
fetch_commons
log "derived variants"
derive
log "generated set"
generate
# The origin serves these files as another user, so every one has to be
# readable, and a file curl wrote under a strict umask is not.
chmod a+rX "$FILES"
chmod a+r "$FILES"/* 2>/dev/null || true

log "classify"
classify

rm -rf "$WORK"

log "corpus"
{
    printf 'files    %s\n' "$(( $(wc -l < "$MANIFEST") - 1 ))"
    printf 'bytes    %s\n' "$(du -sh "$FILES" | cut -f1)"
    printf '\nby class\n'
    tail -n +2 "$MANIFEST" | cut -f4 | sort | uniq -c | sort -rn
    printf '\nby format\n'
    tail -n +2 "$MANIFEST" | cut -f2 | sort | uniq -c | sort -rn | head -25
} >&2

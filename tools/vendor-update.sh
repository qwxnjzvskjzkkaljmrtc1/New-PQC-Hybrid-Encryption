#!/usr/bin/env bash
# vendor-update.sh — ritual pembaruan pustaka vendor/ (butir E.2).
#
# Pemakaian (dari mana saja; script cd sendiri ke root repo):
#   tools/vendor-update.sh check                      Verifikasi HASHES.txt
#   tools/vendor-update.sh regen                      Tulis ulang HASHES.txt dari isi vendor/ sekarang
#   tools/vendor-update.sh update <pkg> <versi>       Unduh & pasang versi baru satu paket, lalu uji
#       pkg: noble-hashes | noble-curves | noble-post-quantum | qrcode-generator
#
# Yang dilakukan mode update:
#   1. unduh tarball resmi dari registry.npmjs.org ke folder temp
#   2. salin himpunan file .js yang dibutuhkan (closure import dari daftar
#      lama di HASHES.txt, supaya dependensi internal baru ikut otomatis)
#   3. tulis ulang import '@noble/<x>/...' menjadi path relatif antar-folder
#      (sesuai catatan "Modifikasi lokal" di vendor/README.txt)
#   4. laporkan perbandingan hash lama vs baru per file
#   5. perbarui referensi folder versi di crypto.js / argon2-worker.js / sw.js
#   6. regenerate HASHES.txt, jalankan node tests/qekh.test.mjs
#   7. gagal -> ROLLBACK penuh; sukses -> catat di vendor/UPGRADE-LOG.txt
set -euo pipefail

cd "$(dirname "$0")/.."
VENDOR=vendor
HASHES="$VENDOR/HASHES.txt"
LOG="$VENDOR/UPGRADE-LOG.txt"
REFS="crypto.js argon2-worker.js sw.js"

# Registry npm bisa dialihkan (mirror lokal / tes): QEKH_NPM_REGISTRY=file:///...
NPM_REGISTRY=${QEKH_NPM_REGISTRY:-https://registry.npmjs.org}

die() { echo "ERROR: $*" >&2; exit 1; }

case "${1:-}" in
    check|regen|update) ;;
    *) sed -n '2,20p' "$0"; exit 1 ;;
esac

# --- util ------------------------------------------------------------
pkg_url() { # <pkg> <versi> -> URL tarball npm
    case "$1" in
        noble-hashes)       echo "$NPM_REGISTRY/@noble/hashes/-/hashes-$2.tgz" ;;
        noble-curves)       echo "$NPM_REGISTRY/@noble/curves/-/curves-$2.tgz" ;;
        noble-post-quantum) echo "$NPM_REGISTRY/@noble/post-quantum/-/post-quantum-$2.tgz" ;;
        qrcode-generator)   echo "$NPM_REGISTRY/qrcode-generator/-/qrcode-generator-$2.tgz" ;;
        *) die "paket tidak dikenal: $1" ;;
    esac
}

folder_of() { # <pkg> -> folder vendor/<pkg>-<versi> yang ada (harus tepat satu)
    local found
    found=$(find "$VENDOR" -maxdepth 1 -type d -name "$1-*" | sort)
    [ "$(printf '%s\n' "$found" | grep -c .)" -eq 1 ] || die "folder $VENDOR/$1-* tidak tepat satu: $found"
    echo "$found"
}

regen_hashes() {
    ( cd "$VENDOR" && find . -name '*.js' -type f | LC_ALL=C sort | xargs sha256sum ) > "$HASHES.tmp"
    mv "$HASHES.tmp" "$HASHES"
    echo "HASHES.txt ditulis ulang ($(wc -l < "$HASHES" | tr -d ' ') file)."
}

# closure import relatif dalam satu paket: mulai dari daftar awal, ikuti
# import './...' / '../<dalam-paket>/...' sampai stabil (maks 20 putaran)
close_imports() { # <dir-ekstrak-package> <daftar-file-awal...>
    local src=$1; shift
    local -A want=()
    local f changed=1 round=0 dep rel base target
    for f in "$@"; do want["$f"]=1; done
    while [ "$changed" = 1 ] && [ $round -lt 20 ]; do
        changed=0; round=$((round + 1))
        for f in "${!want[@]}"; do
            [ -f "$src/$f" ] || continue
            # tangkap from './x.js' / import './x.js' / from '../x.js'
            while IFS= read -r dep; do
                case "$dep" in
                    ./*|../*) ;;
                    *) continue ;;
                esac
                base=$(dirname "$f")
                target=$(cd "$src/$base" 2>/dev/null && cd "$(dirname "$dep")" 2>/dev/null && pwd -P)/$(basename "$dep") || continue
                rel=${target#"$src"/}
                case "$rel" in
                    "$src"*|/*|..*) continue ;;  # di luar paket ini
                esac
                [ -f "$src/$rel" ] || continue
                if [ -z "${want[$rel]:-}" ]; then
                    want["$rel"]=1; changed=1
                    echo "  + dependensi internal baru terdeteksi: $rel" >&2
                fi
            done < <(grep -oE "(from|import)[[:space:]]+['\"][^'\"]+['\"]" "$src/$f" \
                     | sed -E "s/(from|import)[[:space:]]+['\"]//; s/['\"]$//")
        done
    done
    printf '%s\n' "${!want[@]}" | LC_ALL=C sort
}

# tulis ulang import '@noble/<x>/path' -> '../<folder-vendor-x>/path'
# Paket yang sedang diupdate harus menunjuk ke folder BARU (folder lamanya
# masih ada saat fungsi ini dipanggil). Paket lain memakai folder yang ada.
rewrite_imports() { # <folder-baru> <pkg-sendiri> <nama-folder-baru>
    local dir=$1 selfpkg=$2 selfname=$3
    local pkg folder scope
    local -a sed_args=()
    for pkg in noble-hashes noble-curves noble-post-quantum; do
        case "$pkg" in
            noble-hashes)       scope="@noble/hashes" ;;
            noble-curves)       scope="@noble/curves" ;;
            noble-post-quantum) scope="@noble/post-quantum" ;;
        esac
        if [ "$pkg" = "$selfpkg" ]; then
            folder=$selfname
        else
            folder=$(find "$VENDOR" -maxdepth 1 -type d -name "$pkg-*" | sort | head -1)
            [ -n "$folder" ] || continue   # paket tidak dipakai repo ini — lewati
            folder=$(basename "$folder")
        fi
        sed_args+=(-e "s|$scope/|../$folder/|g")
    done
    [ "${#sed_args[@]}" -gt 0 ] || return 0
    find "$dir" -name '*.js' -type f | while read -r f; do
        sed -i "${sed_args[@]}" "$f"
    done
}

# ---------------------------------------------------------------------
case "$1" in
check)
    ( cd "$VENDOR" && sha256sum -c HASHES.txt )
    echo "Semua hash vendor cocok."
    ;;
regen)
    regen_hashes
    ;;
update)
    PKG=${2:?} ; VER=${3:?}
    [[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "versi harus berbentuk X.Y.Z (dapat: $VER)"
    command -v curl >/dev/null || die "curl tidak ditemukan"
    command -v tar  >/dev/null || die "tar tidak ditemukan"

    OLD_DIR=$(folder_of "$PKG")
    OLD_NAME=$(basename "$OLD_DIR")
    NEW_NAME="$PKG-$VER"
    NEW_DIR="$VENDOR/$NEW_NAME"
    [ "$OLD_NAME" != "$NEW_NAME" ] || die "versi $VER sudah terpasang ($OLD_NAME)"
    [ ! -e "$NEW_DIR" ] || die "$NEW_DIR sudah ada — hapus dulu bila ingin mengulang."

    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT

    echo "== 1/7 unduh $PKG $VER =="
    URL=$(pkg_url "$PKG" "$VER")
    curl -fsSL "$URL" -o "$TMP/pkg.tgz" || die "unduh gagal: $URL"
    tar -xzf "$TMP/pkg.tgz" -C "$TMP"
    [ -d "$TMP/package" ] || die "struktur tarball tak dikenal (tidak ada folder package/)"

    echo "== 2/7 salin himpunan file yang dibutuhkan =="
    # daftar awal = file paket ini yang tercatat di HASHES.txt sekarang
    mapfile -t INITIAL < <(awk -v p="./$OLD_NAME/" 'index($2, p) == 1 { print substr($2, length(p) + 1) }' "$HASHES")
    [ "${#INITIAL[@]}" -gt 0 ] || die "tidak ada file $OLD_NAME di HASHES.txt"
    mapfile -t FILES < <(close_imports "$TMP/package" "${INITIAL[@]}")
    mkdir -p "$NEW_DIR"
    for f in "${FILES[@]}"; do
        [ -f "$TMP/package/$f" ] || die "file $f hilang di versi $VER — periksa perubahan struktur paket secara manual"
        mkdir -p "$NEW_DIR/$(dirname "$f")"
        cp "$TMP/package/$f" "$NEW_DIR/$f"
    done
    echo "  ${#FILES[@]} file disalin ke $NEW_DIR"

    echo "== 3/7 tulis ulang import @noble/* =="
    rewrite_imports "$NEW_DIR" "$PKG" "$NEW_NAME"

    echo "== 4/7 perbandingan hash lama -> baru =="
    CHANGES="$TMP/changes.txt"; : > "$CHANGES"
    for f in "${FILES[@]}"; do
        old=$(awk -v p="./$OLD_NAME/$f" '$2 == p { print $1 }' "$HASHES")
        new=$(sha256sum "$NEW_DIR/$f" | cut -d' ' -f1)
        if [ -z "$old" ]; then st="BARU   "
        elif [ "$old" = "$new" ]; then st="SAMA   "
        else st="BERUBAH"; fi
        printf '  %s %s\n' "$st" "$f"
        [ "$st" = "BERUBAH" ] && printf '%s -> %s  %s\n' "$old" "$new" "$f" >> "$CHANGES"
    done

    echo "== 5/7 pasang & perbarui referensi =="
    BACKUP="$TMP/backup"; mkdir -p "$BACKUP"
    cp "$HASHES" "$BACKUP/HASHES.txt"
    for r in $REFS; do cp "$r" "$BACKUP/$(basename "$r")"; done
    mv "$OLD_DIR" "$BACKUP/$OLD_NAME"
    for r in $REFS; do
        sed -i "s|$OLD_NAME|$NEW_NAME|g" "$r"
    done
    regen_hashes

    echo "== 6/7 jalankan tes =="
    if node tests/qekh.test.mjs; then
        echo "== 7/7 sukses — mencatat log =="
        {
            echo "------------------------------------------------------------"
            echo "$(date -u '+%Y-%m-%d %H:%M UTC')  $PKG: $OLD_NAME -> $NEW_NAME"
            echo "  URL: $URL"
            if [ -s "$CHANGES" ]; then cat "$CHANGES"; else echo "  (tidak ada file yang berubah hash-nya)"; fi
        } >> "$LOG"
        echo "Selesai. Folder lama & backup ada di $TMP hingga shell ini keluar —"
        echo "tinjau 'git status', lalu commit bila puas."
    else
        echo "== 7/7 TES GAGAL — ROLLBACK ==" >&2
        rm -rf "$NEW_DIR"
        mv "$BACKUP/$OLD_NAME" "$OLD_DIR"
        cp "$BACKUP/HASHES.txt" "$HASHES"
        for r in $REFS; do cp "$BACKUP/$(basename "$r")" "$r"; done
        die "versi $VER tidak lolos tes; semua perubahan sudah dibatalkan."
    fi
    ;;
esac

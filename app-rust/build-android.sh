#!/usr/bin/env bash
# Сборка native-библиотеки NeXX (libnexxapp.so) под Android через NDK.
#
# Ключевой момент: крейт ring (C-часть) собирается кросс-компилятором через
# cc-rs. Без переменных CC_*/AR_* cc-rs берёт ХОСТОВЫЙ cc, и сборка падает с
#   fatal error: 'bits/libc-header-start.h' file not found
# (хостовые glibc-заголовки вместо sysroot NDK). Ниже выставляем NDK-тулчейн.
#
# usage: ./build-android.sh [target ...]   (по умолчанию все три ABI)
set -euo pipefail

NDK=${ANDROID_NDK_HOME:-/home/thomas/build/android-sdk/ndk/28.2.13676358}
BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
cd "$(dirname "$0")"
# Свои артефакты — в каталоге проекта, а не в общем ~/.build/cache/cargo-target.
export CARGO_TARGET_DIR="$(pwd)/target"
unset CC AR RANLIB CFLAGS CXX 2>/dev/null || true

TARGETS=${*:-"aarch64-linux-android armv7-linux-androideabi x86_64-linux-android"}

for t in $TARGETS; do
  case "$t" in
    aarch64-linux-android)
      CC="$BIN/aarch64-linux-android35-clang"; KEY=aarch64_linux_android; TRIPLE=aarch64-linux-android35 ;;
    armv7-linux-androideabi)
      CC="$BIN/armv7a-linux-androideabi35-clang"; KEY=armv7_linux_androideabi; TRIPLE=armv7a-linux-androideabi35 ;;
    x86_64-linux-android)
      CC="$BIN/x86_64-linux-android35-clang"; KEY=x86_64_linux_android; TRIPLE=x86_64-linux-android35 ;;
    *) echo "!! неизвестный target: $t" >&2; exit 1 ;;
  esac

  echo "=== NeXX native: $t (NDK $(basename "$NDK")) ==="
  env \
    "CC_${KEY}=$CC" \
    "AR_${KEY}=$BIN/llvm-ar" \
    "RANLIB_${KEY}=$BIN/llvm-ranlib" \
    "CFLAGS_${KEY}=--target=$TRIPLE -fPIC" \
    "CXX_${KEY}=${CC/clang/clang++}" \
    cargo build --release --target "$t"

  out="target/$t/release/libnexxapp.so"
  # Аудит M5: в релизном .so не должно быть абсолютных путей сборки.
  # Часть строк (ENGINESDIR и т.п.) приходит из vendored OpenSSL — заменяем
  # префикс на нейтральный СТРОГО ТОЙ ЖЕ ДЛИНЫ: сдвиг байтов ломает ELF
  # (секционные оффсеты перестают совпадать → "file too short" в nm).
  if [ -f "$out" ]; then
    python3 - "$out" <<'PYEOF'
import sys
p = sys.argv[1]
data = open(p, 'rb').read()
old = b"/home/thomas"
# Замена той же длины, что и "/home/thomas" (12 байт): "/opt/nexx000".
new = b"/opt/nexx000"
assert len(new) == len(old), f"replacement must be {len(old)} bytes, got {len(new)}"
n = data.count(old)
if n:
    out = data.replace(old, new)
    assert len(out) == len(data), "size changed — binary would be corrupted"
    open(p, 'wb').write(out)
print(f"paths scrubbed in {p}: {n} (size preserved: {len(data)})")
PYEOF
  fi
  # Приёмка: .so после чистки должен остаться валидным ELF с JNI-экспортами.
  # grep -c (а не -q): -q завершает пайп раньше, nm ловит SIGPIPE и при pipefail
  # проверка ложно падает.
  if [ -f "$out" ]; then
    SZ=$(stat -c%s "$out")
    NJNI=$(nm -D "$out" 2>/dev/null | grep -c "Java_")
    if [ "${NJNI:-0}" -gt 0 ]; then
      echo "OK: $out ($SZ байт, ELF валиден, JNI-экспортов: $NJNI)"
    else
      echo "FAIL: $out ($SZ байт) — ELF повреждён после чистки путей" >&2
      exit 1
    fi
  fi
done

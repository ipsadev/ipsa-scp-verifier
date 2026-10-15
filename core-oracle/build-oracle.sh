#!/bin/sh
set -eu

CORE=${CORE:-/src/stellar-core}
OUT=${OUT:-/src/oracle}
JOBS=${JOBS:-$(nproc)}

BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

cd "$CORE"

make -C lib/xdrpp -j"$JOBS"
make -C lib/libsodium -j"$JOBS"
make -C src -j"$JOBS" $(cd src && ls protocol-curr/xdr/*.x | sed 's/\.x$/.h/')
make -C src -j"$JOBS" rust/RustBridge.h
make -C src -j"$JOBS" \
  scp/LocalNode.o scp/SCP.o scp/Slot.o scp/BallotProtocol.o \
  scp/NominationProtocol.o scp/SCPDriver.o scp/QuorumSetUtils.o \
  crypto/SHA.o crypto/Hex.o crypto/KeyUtils.o crypto/Random.o \
  crypto/SecretKey.o crypto/ShortHash.o crypto/StrKey.o crypto/BLAKE2.o \
  util/GlobalChecks.o util/HashOfHash.o util/Logging.o util/Math.o \
  util/RandHasher.o util/numeric.o util/types.o util/Timer.o \
  util/ProtocolVersion.o util/Scheduler.o

rm -f src/util/Backtrace.o

CORE_FLAGS="-O2 -std=c++20 -pthread -DUSE_SPDLOG -DFMT_HEADER_ONLY=1 -DHAVE_CONFIG_H \
  -I . -I src -I src/protocol-curr -isystem lib/xdrpp -isystem lib/fmt/include \
  -isystem lib/libsodium/src/libsodium/include -isystem lib/spdlog/include \
  -isystem lib/tracy/public/tracy -isystem lib"

clang++ -c $CORE_FLAGS -o "$BUILD"/oracle.o /work/oracle.cpp
clang++ -c $CORE_FLAGS -o "$BUILD"/stubs.o /work/stubs.cpp
clang++ -c -O2 -std=c++20 -pthread -DASIO_SEPARATE_COMPILATION=1 -DASIO_STANDALONE \
  -isystem lib/asio/asio/include -o "$BUILD"/asio.o lib/asio/asio/src/asio.cpp
clang++ -c -O2 -std=c++20 -I . -isystem lib -o "$BUILD"/jsoncpp.o lib/json/jsoncpp.cpp
clang++ -c -O2 -std=c++20 -I . -isystem lib -isystem lib/util -o "$BUILD"/crc16.o lib/util/crc16.cpp
clang++ -c -O2 -std=c++20 -I . -isystem lib -isystem lib/util -o "$BUILD"/siphash.o lib/util/siphash.cpp
for f in lib/spdlog/src/*.cpp; do
  clang++ -c -O2 -std=c++20 -DSPDLOG_COMPILED_LIB -DFMT_HEADER_ONLY=1 \
    -isystem lib/spdlog/include -isystem lib/fmt/include \
    -o "$BUILD/spdlog_$(basename "$f" .cpp).o" "$f"
done

clang++ -o "$OUT" "$BUILD"/*.o src/scp/*.o src/crypto/*.o src/util/*.o \
  lib/xdrpp/xdrpp/libxdrpp.a lib/libsodium/src/libsodium/.libs/libsodium.a -lpthread

"$OUT" </dev/null
echo "built $OUT"

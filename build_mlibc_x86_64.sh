#! /bin/sh

set -ex

cd mlibc

rm -rf build-$ARCH
mkdir build-$ARCH && cd build-$ARCH

cat <<EOF >cc
#! /bin/sh
$CC $MLIBC_CFLAGS "\$@"
EOF
chmod +x cc
unset CC

cat <<EOF >c++
#! /bin/sh
$CXX $MLIBC_CXXFLAGS "\$@"
EOF
chmod +x c++
unset CXX

export PATH="$(pwd -P):$PATH"

cat <<EOF >cross_file.txt
[binaries]
c = '$(pwd -P)/cc'
cpp = '$(pwd -P)/c++'

[host_machine]
system = 'aether'
cpu_family = '$ARCH'
cpu = '$ARCH'
endian = 'little'
EOF

unset CFLAGS
unset CXXFLAGS

meson setup .. \
    --cross-file cross_file.txt \
    --buildtype=custom \
    --prefix="${ROOT_DIR}"/libc-$ARCH \
    -Ddefault_library=static

ninja -v
ninja install

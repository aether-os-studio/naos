git clone https://github.com/void-linux/xbps
cd xbps
./configure --enable-rpath --prefix=/usr --sysconfdir=/etc
make -j$(nproc)
make DESTDIR=$(pwd)/../xbps-bin/ install

# tcptrace-sce

This repo is a copy of https://gitlab.quatermass.co.uk/jgh/tcptrace along with modifications
for SCE (Some Congestion Experienced).

The resulting xplot files generated must be plotted using the xplot version from
https://gitlab.quatermass.co.uk/jgh/xplot.

## Building

```
sudo apt-get install build-essential libpcap-dev # might be other dependencies
autoconf
./configure
make
sudo make install
```

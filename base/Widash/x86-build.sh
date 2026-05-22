#!/usr/bin/env bash
set -x
mkdir -p archbuilds
rm -f archbuilds/dash*

export CFLAGS="-m32"
export LDFLAGS="-m32"
OUTEXT=32
if ! ./configure --enable-static; then
    printf "\033[32mCONFIGURE FAILED on $CC\033[0m"
    exit 32
fi

make clean
if ! make -j$(nproc); then
    printf "\033[32mBUILD FAILED on $CC\033[0m"
    exit 32
fi

cp src/dash archbuilds/dash.${OUTEXT}

unset CFLAGS
unset LDFLAGS
make clean

###################### x86 64 bit
export CFLAGS="-m64"
export LDFLAGS="-m64"
OUTEXT=""
if ! ./configure --enable-static; then
    printf "\033[32mCONFIGURE FAILED on $CC\033[0m"
    exit 64
fi

make clean
if ! make -j$(nproc); then
    printf "\033[32mBUILD FAILED on $CC\033[0m"
    exit 64
fi
cp src/dash archbuilds/dash

unset CLAGS
unset LDFLAGS


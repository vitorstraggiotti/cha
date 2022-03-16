#!/bin/bash

CONTROLFILE=./cha_3.0.0_amd64/DEBIAN/control
BINPATH=./cha_3.0.0_amd64/usr/bin

mkdir -p "$(dirname $CONTROLFILE)" && touch "$CONTROLFILE"
mkdir -p "$BINPATH"

cp ./cha ./cha_3.0.0_amd64/usr/bin/

echo "Package: cha" >> $CONTROLFILE
echo "Version: 3.0.0" >> $CONTROLFILE
echo "Architecture: all" >> $CONTROLFILE
echo "Essential: no" >> $CONTROLFILE
echo "Priority: optional" >> $CONTROLFILE
echo "Depends: " >> $CONTROLFILE
echo "Maintainer: Vitor Henrique A. H. S. Silva" >> $CONTROLFILE
echo "Description: Encrypt and decrypt files using chacha algorithm" >> $CONTROLFILE

## preinst and postinst ca be added
#echo "" >> ./cha_3.0.0_amd64/DEBIAN/postinst
#chmod 755 ./cha_3.0.0_amd64/DEBIAN/postinst

## Generate package
dpkg-deb --build cha_3.0.0_amd64

## Cleaning generated files
rm -r cha_3.0.0_amd64

#!/bin/bash

mkdir cha_3.0.0_amd64
mkdir ./cha_3.0.0/DEBIAN
mkdir ./cha_3.0.0_amd64/usr
mkdir ./cha_3.0.0 amd64/usr/bin

#cp ./cha ./cha_3.0.0_amd64/usr/bin/

echo "Package: cha" >> ./cha_3.0.0_amd64/DEBIAN/control
echo "Version: 3.0.0" >> ./cha_3.0.0_amd64/DEBIAN/control
echo "Architecture: all" >> ./cha_3.0.0_amd64/DEBIAN/control
echo "Essential: no" >> ./cha_3.0.0_amd64/DEBIAN/control
echo "Priority: optional" >> ./cha_3.0.0_amd64/DEBIAN/control
echo "Depends: " >> ./cha_3.0.0_amd64/DEBIAN/control
echo "Maintainer: Vitor Henrique A. H. S. Silva" >> ./cha_3.0.0_amd64/DEBIAN/control
echo "Description: Encrypt and decrypt files using chacha algorithm" >> ./cha_3.0.0_amd64/DEBIAN/control

## preinst and postinst ca be added
#echo "" >> ./cha_3.0.0_amd64/DEBIAN/postinst
#chmod 755 ./cha_3.0.0_amd64/DEBIAN/postinst

## Generate package
#dpkg-deb --build cha_3.0.0_amd64

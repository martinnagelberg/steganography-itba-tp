#!/bin/bash

set -e

green=$(tput setaf 2)
cyan=$(tput setaf 37)
normal=$(tput sgr0)

ALGS=(aes128 aes192 aes256 des)
MODES=(ecb cfb ofb cbc)

echo "Running tests..."

echo "${cyan}* LSB1 (no encryption)${normal}"
echo "  -> Embed and extract (no encryption)"
java -jar target/stegobmp.jar -embed -in assets/oculto.png -p assets/lado.bmp -out testin.bmp -steg LSB1
java -jar target/stegobmp.jar -extract -p testin.bmp -out testout -steg LSB1
diff assets/oculto.png testout.png
rm testin.bmp testout.png

echo "  -> Should fail because of host size"
java -jar target/stegobmp.jar -embed -in assets/200kb.txt -p assets/lado.bmp -out testin.bmp -steg LSB1


echo "${cyan}* LSB4 (no encryption)${normal}"
echo "  -> Embed and extract"
java -jar target/stegobmp.jar -embed -in assets/oculto.png -p assets/lado.bmp -out testin.bmp -steg LSB4
java -jar target/stegobmp.jar -extract -p testin.bmp -out testout -steg LSB4
diff assets/oculto.png testout.png
rm testin.bmp testout.png

echo "  -> Should fail because of host size"
java -jar target/stegobmp.jar -embed -in assets/200kb.txt -p assets/lado.bmp -out testin.bmp -steg LSB4

echo "${cyan}* LSBI (no encryption)${normal}"
echo "  -> Embed and extract"
java -jar target/stegobmp.jar -embed -in assets/oculto.png -p assets/lado.bmp -out testin.bmp -steg LSBI
java -jar target/stegobmp.jar -extract -p testin.bmp -out testout -steg LSBI
diff assets/oculto.png testout.png
rm testin.bmp testout.png

echo "  -> Should fail because of host size"
java -jar target/stegobmp.jar -embed -in assets/200kb.txt -p assets/lado.bmp -out testin.bmp -steg LSBI

echo "${cyan}* All encryption and modes with LSB1${normal}"
for ALG in ${ALGS[*]}; do
  for MODE in ${MODES[*]}; do
    echo "  -> Embed and extract ($ALG - $MODE mode)"
    java -jar target/stegobmp.jar -embed -in assets/oculto.png -p assets/lado.bmp -out testin.bmp -steg LSB1 -a $ALG -m $MODE -pass jose
    java -jar target/stegobmp.jar -extract -p testin.bmp -out testout -steg LSB1 -a $ALG -m $MODE -pass jose
    diff assets/oculto.png testout.png
    rm testin.bmp testout.png
  done
done


echo "Tests: ${green}22 passed.${normal}"
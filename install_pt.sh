mkdir build 2> /dev/null
cd build
rm -rf ./*
cmake ../
make
rm ../afl-pt/libpt.a
cp pt/libpt.a ../afl-pt/
#rm ../afl-pt/pt.h
cp ../pt/*.h ../afl-pt/


cd ../afl-pt
make clean
make
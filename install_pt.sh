# build libpt.a
cd pt/
rm CMakeCache.txt 2> /dev/null
cmake .
make

# copy libpt.a and *.h to afl-pt/
rm ../afl-pt/libpt.a
cp libpt.a ../afl-pt/
cp *.h ../afl-pt/

# rebuild afl-pt
cd ../afl-pt
make clean
make
cd ../
reconfigure
./configure
make
cd src
./dummycoder --no-ciphering --data-path data/setup_1162
./dummycoder --no-ciphering --data-path data/setup_1162.xcch.enc
./dummycoder --no-ciphering --data-path data/setup_1162.facch.enc


#autoreconf
#./configure
#make

if [ $# -eq 0 ]
  then
    echo "No arguments supplied, need filepath"
    exit
fi

src/dummycoder --no-ciphering --substep-output --data-path $1
src/dummycoder --no-ciphering --data-path $1.xcch.burstmap
src/dummycoder --no-ciphering --data-path $1.facch.burstmap



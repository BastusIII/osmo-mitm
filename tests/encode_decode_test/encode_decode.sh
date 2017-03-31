data_path="$(pwd)/test_data/data"

../../src/dummycoder --no-ciphering --data-type plain --data-path $data_path 
../../src/dummycoder --no-ciphering --data-type burstmap_xcch --data-path "$data_path.xcch.burstmap"
../../src/dummycoder --no-ciphering --data-type burstmap_facch --data-path "$data_path.facch.burstmap"



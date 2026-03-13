cmake -S . -B build
cmake --build build
sudo rm /lib/security/pam_parallel_fprint.so
sudo cp build/pam_parallel_fprint.so /lib/security/

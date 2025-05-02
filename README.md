# ZKFocil with Barretenberg

### Instructions for running the zkfocil test

1. Install barretenberg
   - Installing and building barretenberg locally on MacOS is likely to run into issues. Use a Linux machine if possible. (Note: I have set up a GCP VM instance (n2-standard-4 (4 vCPUs, 16 GB memory)) for us to compile and build on barretenberg.)
   - Install dependencies: `sudo apt-get install cmake clang clang-format ninja-build libstdc++-12-dev`
   - Top-level bootstrap: run `./bootstrap.sh` in `bberg` (This takes a long time to compile, if you wish to skip, just make sure you check the required toolchains and their versions, see the function [`check_toolchains`](../zkFOCIL-impl/bberg/bootstrap.sh).)
   - Local bootstrap: run `./bootstrap.sh` in `bberg/barretenberg/cpp` (This also takes a long time to compile everything in barretenberg, but its recommended to run this once.)
2. Running ZKFocil tests:
   - Compile: `cmake --build --preset default --target stdlib_zkfocil_tests`
   - Run tests: `(cd build && ./bin/stdlib_zkfocil_tests)` (Note that the parentheses mean that bash runs the test command in a subshell)
   - Run specific test(s): `(cd build && ./bin/stdlib_zkfocil_tests --gtest_filter=*keyword*)` (This will run all tests with names that contain `keyword`.)
3. IPA integration:
   - WIP WIP

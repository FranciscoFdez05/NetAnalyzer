# ctest --test-dir build -C Release --output-on-failure
add_executable(netanalyzer_tests tests.cpp)
target_link_libraries(netanalyzer_tests PRIVATE netanalyzer_core)
netanalyzer_set_warnings(netanalyzer_tests)
add_test(NAME netanalyzer_tests COMMAND netanalyzer_tests)

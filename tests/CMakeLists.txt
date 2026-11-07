add_executable(miniips_cli_tests test_cli.cpp)
target_link_libraries(miniips_cli_tests PRIVATE miniips_cli GTest::gtest_main)

add_executable(miniips_parser_tests test_packet_parser.cpp)
target_link_libraries(miniips_parser_tests PRIVATE miniips_packet GTest::gtest_main)

add_executable(miniips_capture_tests test_pcap_source.cpp test_cli_pcap.cpp test_cli_flow.cpp
    test_cli_reassembly.cpp)
target_link_libraries(miniips_capture_tests PRIVATE miniips_cli GTest::gtest_main)

add_executable(miniips_flow_tests test_flow_table.cpp)
target_link_libraries(miniips_flow_tests PRIVATE miniips_flow GTest::gtest_main)

add_executable(miniips_reassembly_tests test_tcp_reassembler.cpp test_reassembly_lifecycle.cpp)
target_link_libraries(miniips_reassembly_tests PRIVATE miniips_reassembly GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(miniips_cli_tests PROPERTIES TIMEOUT 10)
gtest_discover_tests(miniips_parser_tests PROPERTIES TIMEOUT 10)
gtest_discover_tests(miniips_capture_tests PROPERTIES TIMEOUT 10)
gtest_discover_tests(miniips_flow_tests PROPERTIES TIMEOUT 10)
gtest_discover_tests(miniips_reassembly_tests PROPERTIES TIMEOUT 10)

foreach(cli_case IN ITEMS help version missing unknown missing_pcap_input extra_arguments)
    add_test(NAME cli.${cli_case}
        COMMAND "${CMAKE_COMMAND}"
            "-DMINIIPS_EXECUTABLE=$<TARGET_FILE:miniips>"
            "-DCLI_CASE=${cli_case}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/check_cli.cmake"
    )
    set_tests_properties(cli.${cli_case} PROPERTIES TIMEOUT 10)
endforeach()

foreach(cli_case IN ITEMS bidirectional expired capacity)
    add_test(NAME flow.${cli_case}
        COMMAND "${CMAKE_COMMAND}"
            "-DMINIIPS_EXECUTABLE=$<TARGET_FILE:miniips>"
            "-DFIXTURE_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/fixtures"
            "-DCLI_CASE=${cli_case}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/check_flow_cli.cmake"
    )
    set_tests_properties(flow.${cli_case} PROPERTIES FIXTURES_REQUIRED pcap_files TIMEOUT 10)
endforeach()

add_executable(miniips_fixture_writer fixture_writer.cpp)
add_test(NAME pcap.prepare_fixtures
    COMMAND miniips_fixture_writer "${CMAKE_CURRENT_BINARY_DIR}/fixtures"
)
set_tests_properties(pcap.prepare_fixtures PROPERTIES FIXTURES_SETUP pcap_files TIMEOUT 10)

foreach(cli_case IN ITEMS normal mixed empty truncated unsupported)
    add_test(NAME pcap.${cli_case}
        COMMAND "${CMAKE_COMMAND}"
            "-DMINIIPS_EXECUTABLE=$<TARGET_FILE:miniips>"
            "-DFIXTURE_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/fixtures"
            "-DCLI_CASE=${cli_case}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/check_pcap_cli.cmake"
    )
    set_tests_properties(pcap.${cli_case} PROPERTIES FIXTURES_REQUIRED pcap_files TIMEOUT 10)
endforeach()

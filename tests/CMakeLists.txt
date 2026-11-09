add_executable(miniips_cli_tests test_cli.cpp)
target_link_libraries(miniips_cli_tests PRIVATE miniips_cli GTest::gtest_main)

add_executable(miniips_parser_tests test_packet_parser.cpp)
target_link_libraries(miniips_parser_tests PRIVATE miniips_packet GTest::gtest_main)

add_executable(miniips_capture_tests test_pcap_source.cpp test_cli_pcap.cpp test_cli_flow.cpp
    test_cli_reassembly.cpp test_cli_rules.cpp test_cli_jsonl.cpp test_cli_live.cpp test_cli_inline.cpp)
target_link_libraries(miniips_capture_tests PRIVATE miniips_cli GTest::gtest_main)

add_executable(miniips_flow_tests test_flow_table.cpp)
target_link_libraries(miniips_flow_tests PRIVATE miniips_flow GTest::gtest_main)

add_executable(miniips_reassembly_tests test_tcp_reassembler.cpp test_reassembly_lifecycle.cpp)
target_link_libraries(miniips_reassembly_tests PRIVATE miniips_reassembly GTest::gtest_main)

include(GoogleTest)
add_executable(miniips_nfqueue_lifecycle_tests test_nfqueue_lifecycle.cpp)
target_link_libraries(miniips_nfqueue_lifecycle_tests PRIVATE miniips_cli GTest::gtest_main)
foreach(nfq_function IN ITEMS open bind_pf create_queue set_mode set_queue_maxlen set_queue_flags
        fd destroy_queue close get_msg_packet_hdr set_verdict)
    target_link_options(miniips_nfqueue_lifecycle_tests PRIVATE "LINKER:--wrap=nfq_${nfq_function}")
endforeach()
foreach(queue_syscall IN ITEMS recv ppoll getsockopt recvmsg)
    target_link_options(miniips_nfqueue_lifecycle_tests PRIVATE "LINKER:--wrap=${queue_syscall}")
endforeach()
gtest_discover_tests(miniips_nfqueue_lifecycle_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_nfqueue_config_tests test_nfqueue_config.cpp)
target_link_libraries(miniips_nfqueue_config_tests PRIVATE miniips_nfqueue GTest::gtest_main)
gtest_discover_tests(miniips_nfqueue_config_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_inline_logging_tests test_inline_logging.cpp)
target_link_libraries(miniips_inline_logging_tests PRIVATE miniips_publisher GTest::gtest_main)
gtest_discover_tests(miniips_inline_logging_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_inline_core_tests test_inline_core.cpp)
target_link_libraries(miniips_inline_core_tests PRIVATE miniips_verdict GTest::gtest_main)
gtest_discover_tests(miniips_inline_core_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_live_source_tests test_live_source.cpp)
target_link_libraries(miniips_live_source_tests PRIVATE miniips_packet GTest::gtest_main)
gtest_discover_tests(miniips_live_source_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_live_metadata_tests test_live_metadata.cpp)
target_link_libraries(miniips_live_metadata_tests PRIVATE miniips_publisher GTest::gtest_main)
gtest_discover_tests(miniips_live_metadata_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_publisher_tests test_event_publisher.cpp)
target_link_libraries(miniips_publisher_tests PRIVATE miniips_publisher GTest::gtest_main)
gtest_discover_tests(miniips_publisher_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_logging_tests test_event_logger.cpp)
target_link_libraries(miniips_logging_tests PRIVATE miniips_logging GTest::gtest_main)
gtest_discover_tests(miniips_logging_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_engine_tests test_engine.cpp test_engine_robustness.cpp)
target_link_libraries(miniips_engine_tests PRIVATE miniips_engine GTest::gtest_main)
gtest_discover_tests(miniips_engine_tests PROPERTIES TIMEOUT 10)
add_executable(miniips_rule_tests test_rule_loader.cpp test_rule_engine.cpp test_reassembly_ranges.cpp)
target_link_libraries(miniips_rule_tests PRIVATE miniips_rules GTest::gtest_main)
gtest_discover_tests(miniips_rule_tests PROPERTIES TIMEOUT 10)
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

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME inline.tcp_guard COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/check_inline_guard.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/check_inline_tcp.py")
    set_tests_properties(inline.tcp_guard PROPERTIES TIMEOUT 30)
    add_test(NAME inline.guard COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/check_inline_guard.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/check_inline_process.py")
    set_tests_properties(inline.guard PROPERTIES TIMEOUT 30)
    add_test(NAME live.guard COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/check_live_guard.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/check_live_process.py")
    set_tests_properties(live.guard PROPERTIES TIMEOUT 30)
    add_test(NAME jsonl.process
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_jsonl_process.py"
            "$<TARGET_FILE:miniips>" "${CMAKE_CURRENT_BINARY_DIR}/fixtures"
            "${PROJECT_SOURCE_DIR}/rules/a5-demo.json")
    set_tests_properties(jsonl.process PROPERTIES FIXTURES_REQUIRED pcap_files TIMEOUT 30)
else()
    message(STATUS "Python3 not found: run tests/check_jsonl_process.py manually for A5 process checks.")
endif()

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

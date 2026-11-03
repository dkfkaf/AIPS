if(NOT DEFINED MINIIPS_EXECUTABLE OR NOT EXISTS "${MINIIPS_EXECUTABLE}")
    message(FATAL_ERROR "The miniips executable is missing.")
endif()

set(expected_exit 0)
if(CLI_CASE STREQUAL "help")
    set(arguments --help)
    set(expected_output "Usage: miniips")
elseif(CLI_CASE STREQUAL "version")
    set(arguments --version)
    set(expected_output "^miniips [0-9]+\\.[0-9]+\\.[0-9]+\n$")
elseif(CLI_CASE STREQUAL "missing")
    set(arguments)
    set(expected_exit 2)
elseif(CLI_CASE STREQUAL "unknown")
    set(arguments --unknown)
    set(expected_exit 2)
elseif(CLI_CASE STREQUAL "missing_pcap_input")
    set(arguments --mode pcap)
    set(expected_exit 2)
elseif(CLI_CASE STREQUAL "extra_arguments")
    set(arguments --help --version)
    set(expected_exit 2)
else()
    message(FATAL_ERROR "Unknown CLI test case: ${CLI_CASE}")
endif()

execute_process(
    COMMAND "${MINIIPS_EXECUTABLE}" ${arguments}
    RESULT_VARIABLE actual_exit
    OUTPUT_VARIABLE output
    ERROR_VARIABLE errors
    TIMEOUT 5
)

if(NOT "${actual_exit}" STREQUAL "${expected_exit}")
    message(FATAL_ERROR "Expected exit ${expected_exit}, got ${actual_exit}: ${errors}")
endif()

if(expected_exit EQUAL 0)
    if(NOT errors STREQUAL "" OR NOT output MATCHES "${expected_output}")
        message(FATAL_ERROR "Unexpected CLI output: stdout=${output}; stderr=${errors}")
    endif()
else()
    if(NOT output STREQUAL "" OR NOT errors MATCHES "Usage: miniips")
        message(FATAL_ERROR "Invalid arguments must fail with usage on stderr.")
    endif()
endif()

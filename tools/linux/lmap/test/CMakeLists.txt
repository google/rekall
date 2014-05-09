cmake_minimum_required(VERSION 2.8)

set(TEST_FILES host
  host.strtab
  host.strtab.h
  parasite
  parasite.shstrtab
  parasite.shstrtab.h
)

foreach(TEST_FILE ${TEST_FILES})
  configure_file(
    test_data/${TEST_FILE}
    ${CMAKE_BINARY_DIR}/test/test_data/${TEST_FILE}
    COPYONLY
  )
endforeach(TEST_FILE)

add_executable(elfrelink_test elfrelink_test.c)
target_link_libraries(elfrelink_test log elfrelink)


project(ppmon)
add_executable(pppmon main.cpp)
target_link_libraries(pppmon boost_system boost_thread pthread)
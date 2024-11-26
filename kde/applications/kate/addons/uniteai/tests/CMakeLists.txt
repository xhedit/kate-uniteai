add_executable(uniteaitestapp "")
target_include_directories(uniteaitestapp PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/.. ../rapidjson/include)
target_include_directories(uniteaitestapp SYSTEM PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../rapidjson/include)
target_link_libraries(uniteaitestapp PRIVATE kateprivate KF${KF_MAJOR_VERSION}::TextEditor)

target_sources(
  uniteaitestapp
  PRIVATE
    uniteaitestapp.cpp
    ${DEBUG_SOURCES}
)

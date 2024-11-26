kate_add_plugin(uniteaiplugin)
target_compile_definitions(uniteaiplugin PRIVATE TRANSLATION_DOMAIN="uniteai")

target_link_libraries(
  uniteaiplugin
  PRIVATE
    kateprivate
)

include(ECMQtDeclareLoggingCategory)
ecm_qt_declare_logging_category(
  DEBUG_SOURCES
  HEADER uniteai_debug.h
  IDENTIFIER UNITEAI
  CATEGORY_NAME "kateuniteaiplugin"
)
target_sources(uniteaiplugin PRIVATE ${DEBUG_SOURCES})

ki18n_wrap_ui(uniteaiplugin aiconfigwidget.ui)
target_sources(
  uniteaiplugin
  PRIVATE
    uniteaiconfigpage.cpp
    uniteaiplugin.cpp
    uniteaipluginview.cpp

    plugin.qrc
)

if (TARGET Qt6::Core5Compat)
    target_link_libraries(uniteaiplugin PRIVATE Qt6::Core5Compat) # QTextCodec
endif()

if (BUILD_PCH)
    target_precompile_headers(uniteaiplugin REUSE_FROM katepch)
endif()

set(RAPIDJSON_INCLUDES ${CMAKE_CURRENT_LIST_DIR}/rapidjson/include)
target_include_directories(uniteaiplugin SYSTEM PUBLIC ${RAPIDJSON_INCLUDES})

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

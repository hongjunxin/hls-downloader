if(NOT TARGET avformat)
	find_path(AVFORMAT_INCLUDE_DIR libavformat/avformat.h)
	find_library(AVFORMAT_LIBRARY NAMES avformat)

	include(FindPackageHandleStandardArgs)
    # we call find_package(Avformat) so here must use 'Avformat'
	find_package_handle_standard_args(Avformat DEFAULT_MSG AVFORMAT_LIBRARY AVFORMAT_INCLUDE_DIR)

    if(Avformat_FOUND)
        add_library(avformat UNKNOWN IMPORTED)
        set_target_properties(avformat PROPERTIES
            IMPORTED_LOCATION "${AVFORMAT_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${AVFORMAT_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${AVFORMAT_LIBRARIES}"
            IMPORTED_LINK_INTERFACE_LANGUAGES "C")
    endif()
endif()

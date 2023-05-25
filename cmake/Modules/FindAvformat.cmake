if(NOT TARGET avformat)
	find_path(AVFORMAT_INCLUDE_DIR libavformat/avformat.h)
	find_library(AVFORMAT_LIBRARY NAMES avformat)

	include(FindPackageHandleStandardArgs)
	find_package_handle_standard_args(LibAvFormat DEFAULT_MSG AVFORMAT_LIBRARY AVFORMAT_INCLUDE_DIR)

    if(LibAvFormat_FOUND)
        add_library(avformat UNKNOWN IMPORTED)
        set_target_properties(avformat PROPERTIES
            IMPORTED_LOCATION "${AVFORMAT_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${AVFORMAT_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${AVFORMAT_LIBRARIES}"
            IMPORTED_LINK_INTERFACE_LANGUAGES "C")
    endif()
endif()

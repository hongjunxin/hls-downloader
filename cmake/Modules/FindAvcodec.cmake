if(NOT TARGET avcodec)
	find_path(AVCODEC_INCLUDE_DIR libavcodec/avcodec.h)
	find_library(AVCODEC_LIBRARY NAMES avcodec)

	include(FindPackageHandleStandardArgs)
	find_package_handle_standard_args(LibAvCodec DEFAULT_MSG AVCODEC_LIBRARY AVCODEC_INCLUDE_DIR)

    if(LibAvCodec_FOUND)
        add_library(avcodec UNKNOWN IMPORTED)
        set_target_properties(avcodec PROPERTIES
            IMPORTED_LOCATION "${AVCODEC_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${AVCODEC_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${AVCODEC_LIBRARIES}"
            IMPORTED_LINK_INTERFACE_LANGUAGES "C")
    endif()
endif()

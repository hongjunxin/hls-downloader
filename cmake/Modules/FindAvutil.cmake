if(NOT TARGET avutil)
	find_path(AVUTIL_INCLUDE_DIR libavutil/avutil.h)
	find_library(AVUTIL_LIBRARY NAMES avutil)

	include(FindPackageHandleStandardArgs)
	find_package_handle_standard_args(LibAvUtil DEFAULT_MSG AVUTIL_LIBRARY AVUTIL_INCLUDE_DIR)

    if(LibAvUtil_FOUND)
        add_library(avutil UNKNOWN IMPORTED)
        set_target_properties(avutil PROPERTIES
            IMPORTED_LOCATION "${AVUTIL_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${AVUTIL_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${AVUTIL_LIBRARIES}"
            IMPORTED_LINK_INTERFACE_LANGUAGES "C")
    endif()
endif()

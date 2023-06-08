if(NOT TARGET swresample)
	find_path(SWRESAMPLE_INCLUDE_DIR libswresample/swresample.h)
	find_library(SWRESAMPLE_LIBRARY NAMES swresample)

	include(FindPackageHandleStandardArgs)
	find_package_handle_standard_args(Swresample DEFAULT_MSG SWRESAMPLE_LIBRARY SWRESAMPLE_INCLUDE_DIR)

    if(Swresample_FOUND)
        add_library(swresample UNKNOWN IMPORTED)
        set_target_properties(swresample PROPERTIES
            IMPORTED_LOCATION "${SWRESAMPLE_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${SWRESAMPLE_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${SWRESAMPLE_LIBRARIES}"
            IMPORTED_LINK_INTERFACE_LANGUAGES "C")
    endif()
endif()

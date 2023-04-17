if(NOT TARGET curl::curl)
	find_path(CURL_INCLUDE_DIR curl/curl.h)
	find_library(CURL_LIBRARY NAMES curl)

	include(FindPackageHandleStandardArgs)
	find_package_handle_standard_args(LibCURL DEFAULT_MSG CURL_LIBRARY CURL_INCLUDE_DIR)

    if(LibCURL_FOUND)
        add_library(curl::curl UNKNOWN IMPORTED)
        set_target_properties(curl::curl PROPERTIES
            IMPORTED_LOCATION "${CURL_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${CURL_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${CURL_LIBRARIES}"
                IMPORTED_LINK_INTERFACE_LANGUAGES "C")
    endif()
endif()

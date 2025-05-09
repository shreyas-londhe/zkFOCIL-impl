if (NOT(FUZZING))
    add_executable(
        bn254_transparent_srs_gen
        bn254_transparent_srs_gen.cpp
    )

    target_link_libraries(
        bn254_transparent_srs_gen
        PRIVATE
        srs
        ecc
        crypto_sha256
    )
endif()

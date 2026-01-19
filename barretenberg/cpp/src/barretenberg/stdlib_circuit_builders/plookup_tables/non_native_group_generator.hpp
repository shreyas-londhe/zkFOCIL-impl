#pragma once

#include "./types.hpp"
#include "barretenberg/ecc/curves/bn254/fr.hpp"
#include "barretenberg/ecc/curves/bn254/g1.hpp"
#include "barretenberg/ecc/curves/secp256k1/secp256k1.hpp"
#include <array>

namespace bb::plookup::ecc_generator_tables {

template <typename G1> class ecc_generator_table {
  public:
    typedef typename G1::element element;
    /**
     * Store arrays of precomputed 8-bit lookup tables for generator point coordinates (and their endomorphism
     *equivalents)
     **/
    inline static std::array<std::pair<fr, fr>, 256> generator_endo_xlo_table;
    inline static std::array<std::pair<fr, fr>, 256> generator_endo_xhi_table;
    inline static std::array<std::pair<fr, fr>, 256> generator_xlo_table;
    inline static std::array<std::pair<fr, fr>, 256> generator_xhi_table;
    inline static std::array<std::pair<fr, fr>, 256> generator_ylo_table;
    inline static std::array<std::pair<fr, fr>, 256> generator_yhi_table;
    inline static std::array<std::pair<fr, fr>, 256> generator_xyprime_table;
    inline static std::array<std::pair<fr, fr>, 256> generator_endo_xyprime_table;
    inline static bool init = false;

    static void init_generator_tables();

    static size_t convert_position_to_shifted_naf(const size_t position);
    static size_t convert_shifted_naf_to_position(const size_t shifted_naf);
    static std::array<fr, 2> get_xlo_endo_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_xhi_endo_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_xlo_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_xhi_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_ylo_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_yhi_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_xyprime_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_xyprime_endo_values(const std::array<uint64_t, 2> key);
    static BasicTable generate_xlo_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_xhi_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_xlo_endo_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_xhi_endo_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_ylo_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_yhi_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_xyprime_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_xyprime_endo_table(BasicTableId id, const size_t table_index);
    static MultiTable get_xlo_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_xhi_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_xlo_endo_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_xhi_endo_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_ylo_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_yhi_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_xyprime_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_xyprime_endo_table(const MultiTableId id, const BasicTableId basic_id);
};

/**
 * @brief 13-bit generator lookup table for BN254
 *
 * @details Stores 2^13 = 8192 precomputed points for fixed-base scalar multiplication.
 * The 13-bit wNAF is structured so that entries are in the range [0, ..., 8191]
 * The actual scalar value = (wNAF * 2) - 8191
 * Scalar values are from [-8191, -8189, ..., -3, -1, 1, 3, ..., 8189, 8191]
 */
template <typename G1> class ecc_generator_table_13bit {
  public:
    typedef typename G1::element element;
    static constexpr size_t TABLE_SIZE = 8192; // 2^13

    /**
     * Store arrays of precomputed 13-bit lookup tables for generator point coordinates
     * Optimized structure: Each table stores [low 136 bits, high 118 bits]
     * - x coordinate (normal point)
     * - y coordinate (shared between normal and endo point)
     * - x coordinate (endomorphism point, where x_endo = β * x)
     **/
    inline static std::array<std::pair<fr, fr>, TABLE_SIZE> generator_x_table;      // [x_low_136bit, x_high_118bit]
    inline static std::array<std::pair<fr, fr>, TABLE_SIZE> generator_y_table;      // [y_low_136bit, y_high_118bit]
    inline static std::array<std::pair<fr, fr>, TABLE_SIZE> generator_x_endo_table; // [x_endo_low_136bit, x_endo_high_118bit]
    inline static bool init = false;

    static void init_generator_tables();

    static std::array<fr, 2> get_x_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_y_values(const std::array<uint64_t, 2> key);
    static std::array<fr, 2> get_x_endo_values(const std::array<uint64_t, 2> key);

    static BasicTable generate_x_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_y_table(BasicTableId id, const size_t table_index);
    static BasicTable generate_x_endo_table(BasicTableId id, const size_t table_index);

    static MultiTable get_x_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_y_table(const MultiTableId id, const BasicTableId basic_id);
    static MultiTable get_x_endo_table(const MultiTableId id, const BasicTableId basic_id);
};

} // namespace bb::plookup::ecc_generator_tables

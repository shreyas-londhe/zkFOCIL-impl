#pragma once

#include "barretenberg/numeric/bitop/rotate.hpp"

#include "sparse.hpp"
#include "types.hpp"

namespace bb::plookup::blake2s_tables {

static constexpr size_t BITS_PER_SLICE = 5UL;
static constexpr size_t SLICE_SIZE = (1UL << BITS_PER_SLICE);
// Last slice: 2 bits for value + 3 bits for overflow = 5 bits
static constexpr size_t BITS_IN_LAST_SLICE = 5UL;
static constexpr size_t SIZE_OF_LAST_SLICE = (1UL << BITS_IN_LAST_SLICE);

/**
 * This functions performs the operation ROTR^{k}(a ^ b) when filter is false and
 * ROTR^{k}((a % 4) ^ (a % 4)) when filter is true. In other words, (filter = true) implies
 * that the XOR operation works only on the two least significant bits.
 */
template <uint64_t bits_per_slice, uint64_t num_rotated_output_bits, bool filter = false>
inline std::array<bb::fr, 2> get_xor_rotate_values_from_key(const std::array<uint64_t, 2> key)
{
    uint64_t filtered_key0 = filter ? key[0] & 3ULL : key[0];
    uint64_t filtered_key1 = filter ? key[1] & 3ULL : key[1];
    return { uint256_t(numeric::rotate32(uint32_t(filtered_key0) ^ uint32_t(filtered_key1),
                                         uint32_t(num_rotated_output_bits))),
             0ULL };
}

/**
 * Generates a basic 32-bit (XOR + ROTR) lookup table.
 */
template <uint64_t bits_per_slice, uint64_t num_rotated_output_bits, bool filter = false>
inline BasicTable generate_xor_rotate_table(BasicTableId id, const size_t table_index)
{
    const uint64_t base = 1UL << bits_per_slice;
    BasicTable table;
    table.id = id;
    table.table_index = table_index;
    table.use_twin_keys = true;

    for (uint64_t i = 0; i < base; ++i) {
        for (uint64_t j = 0; j < base; ++j) {
            table.column_1.emplace_back(i);
            table.column_2.emplace_back(j);
            uint64_t i_copy = i;
            uint64_t j_copy = j;
            if (filter) {
                i_copy &= 3ULL;
                j_copy &= 3ULL;
            }
            table.column_3.emplace_back(
                uint256_t(numeric::rotate32(uint32_t(i_copy) ^ uint32_t(j_copy), uint32_t(num_rotated_output_bits))));
        }
    }

    table.get_values_from_key = &get_xor_rotate_values_from_key<bits_per_slice, num_rotated_output_bits, filter>;

    table.column_1_step_size = base;
    table.column_2_step_size = base;
    table.column_3_step_size = base;

    return table;
}

/**
 * Generates a multi-lookup-table with 7 slices (5-bit each) for 32-bit XOR operation (a ^ b).
 *
 * Details:
 *
 * With 5-bit slices, we have 7 slices: s0-s5 at 5 bits each (30 bits total),
 * and s6 with 2 bits for value + 3 bits for overflow = 5 bits.
 *
 * The following table summarizes the output bit positions for each slice after rotation.
 * We normalize so that s0's coefficient is 1.
 *
 * -------------------------------------------------
 * | Slice | ROTR_16 | ROTR_12 | ROTR_8  | ROTR_7  |
 * |-------|---------|---------|---------|---------|
 * | s0    | 16      | 20      | 24      | 25      |
 * | s1    | 21      | 25      | 29/0-2  | 30/0-1  |
 * | s2    | 26      | 30/0-2  | 2       | 3       |
 * | s3    | 31/0-3  | 3       | 7       | 8       |
 * | s4    | 4       | 8       | 12      | 13      |
 * | s5    | 9       | 13      | 17      | 18      |
 * | s6    | 14      | 18      | 22      | 23      |
 * -------------------------------------------------
 *
 * We don't need a separate table for ROTR_12 as its output can be derived from an XOR table.
 */
inline MultiTable get_blake2s_xor_table(const MultiTableId id = BLAKE_XOR)
{
    // 7 slices: 6 slices of 5 bits + 1 last slice of 5 bits (2 value + 3 overflow)
    const size_t num_entries = 7;

    std::vector<bb::fr> column_1_coefficients{ bb::fr(1),        bb::fr(1 << 5),  bb::fr(1 << 10),
                                               bb::fr(1 << 15), bb::fr(1 << 20), bb::fr(1 << 25),
                                               bb::fr(1 << 30) };

    MultiTable table(column_1_coefficients, column_1_coefficients, column_1_coefficients);

    table.id = id;
    table.slice_sizes = { SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SIZE_OF_LAST_SLICE };
    table.basic_table_ids = { BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0,
                              BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0_SLICE5_MOD4 };

    for (size_t i = 0; i < num_entries - 1; ++i) {
        table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    }
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_IN_LAST_SLICE, 0, true>);

    return table;
}

/**
 * Generates a multi-lookup-table with 7 slices (5-bit) for 32-bit operation ROTR^{16}(a ^ b).
 *
 * For ROTR^16 with 5-bit slices:
 * - Boundary at bit 16, which is 1 bit into s3 (bits 15-19)
 * - s3 needs ROTR1 (16 - 15 = 1)
 * - Normalizing factor: 2^16 (so s0's coefficient is 1)
 *
 * Output positions: s0→16, s1→21, s2→26, s3→31/0-3, s4→4, s5→9, s6→14
 */
inline MultiTable get_blake2s_xor_rotate_16_table(const MultiTableId id = BLAKE_XOR_ROTATE_16)
{
    constexpr bb::fr coefficient_16 = bb::fr(1) / bb::fr(1 << 16);

    std::vector<bb::fr> column_1_coefficients{ bb::fr(1),        bb::fr(1 << 5),  bb::fr(1 << 10),
                                               bb::fr(1 << 15), bb::fr(1 << 20), bb::fr(1 << 25),
                                               bb::fr(1 << 30) };

    // Coefficients for column 3 (output), normalized by 2^16
    // s0: 2^16/2^16 = 1
    // s1: 2^21/2^16 = 2^5
    // s2: 2^26/2^16 = 2^10
    // s3: uses ROTR1, coefficient 2^(-16) (wraps at bit 31/0)
    // s4: 2^4/2^16 = 2^(-12)
    // s5: 2^9/2^16 = 2^(-7)
    // s6: 2^14/2^16 = 2^(-2)
    std::vector<bb::fr> column_3_coefficients{ bb::fr(1),
                                               bb::fr(1 << 5),
                                               bb::fr(1 << 10),
                                               coefficient_16,
                                               coefficient_16 * bb::fr(1 << 4),
                                               coefficient_16 * bb::fr(1 << 9),
                                               coefficient_16 * bb::fr(1 << 14) };

    MultiTable table(column_1_coefficients, column_1_coefficients, column_3_coefficients);

    table.id = id;
    table.slice_sizes = { SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SIZE_OF_LAST_SLICE };
    // s3 uses ROTR1 (boundary at bit 16, 1 bit into slice s3)
    table.basic_table_ids = { BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE1,
                              BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0_SLICE5_MOD4 };

    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 1>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_IN_LAST_SLICE, 0, true>);

    return table;
}

inline MultiTable get_blake2s_xor_rotate_12_table(const MultiTableId id = BLAKE_XOR_ROTATE_12)
{
    constexpr bb::fr coefficient_20 = bb::fr(1) / bb::fr(1 << 20);

    std::vector<bb::fr> column_1_coefficients{ bb::fr(1),        bb::fr(1 << 5),  bb::fr(1 << 10),
                                               bb::fr(1 << 15), bb::fr(1 << 20), bb::fr(1 << 25),
                                               bb::fr(1 << 30) };


    // Coefficients for column 3 (output), normalized by 2^20
    // s0: 2^20/2^20 = 1
    // s1: 2^25/2^20 = 2^5
    // s2: uses ROTR2, coefficient 2^(-20) (wraps at bit 30/0-2)
    // s3: 2^3/2^20 = 2^(-17)
    // s4: 2^8/2^20 = 2^(-12)
    // s5: 2^13/2^20 = 2^(-7)
    // s6: 2^18/2^20 = 2^(-2)
    std::vector<bb::fr> column_3_coefficients{ bb::fr(1),
                                               bb::fr(1 << 5),
                                               coefficient_20,
                                               coefficient_20 * bb::fr(1 << 3),
                                               coefficient_20 * bb::fr(1 << 8),
                                               coefficient_20 * bb::fr(1 << 13),
                                               coefficient_20 * bb::fr(1 << 18) };

    MultiTable table(column_1_coefficients, column_1_coefficients, column_3_coefficients);

    table.id = id;
    table.slice_sizes = { SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SIZE_OF_LAST_SLICE };
    // s2 uses ROTR2 (boundary at bit 12, 2 bits into slice s2)
    table.basic_table_ids = { BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE2, BLAKE_XOR_ROTATE0,
                              BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0_SLICE5_MOD4 };

    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 2>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_IN_LAST_SLICE, 0, true>);

    return table;
}

/**
 * Generates a multi-lookup-table with 7 slices (5-bit) for 32-bit operation ROTR^{8}(a ^ b).
 *
 * For ROTR^8 with 5-bit slices:
 * - Boundary at bit 8, which is 3 bits into s1 (bits 5-9)
 * - s1 needs ROTR3 (8 - 5 = 3)
 * - Normalizing factor: 2^24 (so s0's coefficient is 1)
 *
 * Output positions: s0→24, s1→29/0-2, s2→2, s3→7, s4→12, s5→17, s6→22
 */
inline MultiTable get_blake2s_xor_rotate_8_table(const MultiTableId id = BLAKE_XOR_ROTATE_8)
{
    constexpr bb::fr coefficient_24 = bb::fr(1) / bb::fr(1 << 24);

    std::vector<bb::fr> column_1_coefficients{ bb::fr(1),        bb::fr(1 << 5),  bb::fr(1 << 10),
                                               bb::fr(1 << 15), bb::fr(1 << 20), bb::fr(1 << 25),
                                               bb::fr(1 << 30) };

    // Coefficients for column 3 (output), normalized by 2^24
    // s0: 2^24/2^24 = 1
    // s1: uses ROTR3, coefficient 2^(-24) (wraps at bit 29/0)
    // s2: 2^2/2^24 = 2^(-22)
    // s3: 2^7/2^24 = 2^(-17)
    // s4: 2^12/2^24 = 2^(-12)
    // s5: 2^17/2^24 = 2^(-7)
    // s6: 2^22/2^24 = 2^(-2)
    std::vector<bb::fr> column_3_coefficients{ bb::fr(1),
                                               coefficient_24,
                                               coefficient_24 * bb::fr(1 << 2),
                                               coefficient_24 * bb::fr(1 << 7),
                                               coefficient_24 * bb::fr(1 << 12),
                                               coefficient_24 * bb::fr(1 << 17),
                                               coefficient_24 * bb::fr(1 << 22) };
    MultiTable table(column_1_coefficients, column_1_coefficients, column_3_coefficients);

    table.id = id;
    table.slice_sizes = { SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SIZE_OF_LAST_SLICE };
    // s1 uses ROTR3 (boundary at bit 8, 3 bits into slice s1)
    table.basic_table_ids = { BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE3, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0,
                              BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0_SLICE5_MOD4 };

    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 3>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_IN_LAST_SLICE, 0, true>);

    return table;
}

/**
 * Generates a multi-lookup-table with 7 slices (5-bit) for 32-bit operation ROTR^{7}(a ^ b).
 *
 * For ROTR^7 with 5-bit slices:
 * - Boundary at bit 7, which is 2 bits into s1 (bits 5-9)
 * - s1 needs ROTR2 (7 - 5 = 2)
 * - Normalizing factor: 2^25 (so s0's coefficient is 1)
 *
 * Output positions: s0→25, s1→30/0-1, s2→3, s3→8, s4→13, s5→18, s6→23
 */
inline MultiTable get_blake2s_xor_rotate_7_table(const MultiTableId id = BLAKE_XOR_ROTATE_7)
{
    constexpr bb::fr coefficient_25 = bb::fr(1) / bb::fr(1 << 25);

    std::vector<bb::fr> column_1_coefficients{ bb::fr(1),        bb::fr(1 << 5),  bb::fr(1 << 10),
                                               bb::fr(1 << 15), bb::fr(1 << 20), bb::fr(1 << 25),
                                               bb::fr(1 << 30) };

    // Coefficients for column 3 (output), normalized by 2^25
    // s0: 2^25/2^25 = 1
    // s1: uses ROTR2, coefficient 2^(-25) (wraps at bit 30/0)
    // s2: 2^3/2^25 = 2^(-22)
    // s3: 2^8/2^25 = 2^(-17)
    // s4: 2^13/2^25 = 2^(-12)
    // s5: 2^18/2^25 = 2^(-7)
    // s6: 2^23/2^25 = 2^(-2)
    std::vector<bb::fr> column_3_coefficients{ bb::fr(1),
                                               coefficient_25,
                                               coefficient_25 * bb::fr(1 << 3),
                                               coefficient_25 * bb::fr(1 << 8),
                                               coefficient_25 * bb::fr(1 << 13),
                                               coefficient_25 * bb::fr(1 << 18),
                                               coefficient_25 * bb::fr(1 << 23) };
    MultiTable table(column_1_coefficients, column_1_coefficients, column_3_coefficients);

    table.id = id;
    table.slice_sizes = { SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SLICE_SIZE, SIZE_OF_LAST_SLICE };
    // s1 uses ROTR2 (boundary at bit 7, 2 bits into slice s1)
    table.basic_table_ids = { BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE2, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0,
                              BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0, BLAKE_XOR_ROTATE0_SLICE5_MOD4 };

    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 2>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_PER_SLICE, 0>);
    table.get_table_values.emplace_back(&get_xor_rotate_values_from_key<BITS_IN_LAST_SLICE, 0, true>);

    return table;
}

} // namespace bb::plookup::blake2s_tables

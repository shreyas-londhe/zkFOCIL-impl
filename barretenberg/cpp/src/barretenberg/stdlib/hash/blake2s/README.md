---
description: >-
  We describe briefly the Blake2s hashing algorithm and note down its
  implementation and design details using lookup tables with 5-bit slices.
---

# Blake2s Using Plookup

### Overview of Blake2s

[Blake2s](https://www.blake2.net/blake2.pdf) hashing supports data of any _byte_ length $$0 \le l < 2^{64}$$. Suppose we have input data of size $$l < 2^{64}$$ bytes. We split it into slices of 64 bytes each and pad it to ensure that the byte-length is a multiple of 64. Blake2s pads the last data block _if and only if_ necessary, with null bytes.  After the required padding, the 64-byte data blocks $$m^0, m^1, \dots, m^{n}$$ where $$n = \left\lceil \frac{l}{64} \right\rceil$$ are used in hashing as:

$$
\begin{aligned}
& h^{0} \leftarrow \text{IV} \oplus P \\
& \text{for } i \in [0,n-1]: \\
& \qquad h^{i+1} \leftarrow \texttt{compress}(h^{i}, m^{i}, l^{i}) \\
& \text{return } h^{n} \in \mathbb{Z}_2^{32 \times 8}
\end{aligned}
$$

Here, $$l^i$$ denotes the lengths of the data block $$m^i$$ _before_ padding. The $$\texttt{compress}$$ function takes three inputs: a 32-byte chaining vector $$h^i = (h^i_0, h^i_1, h^i_2, \dots, h^i_7) \in \mathbb{Z}_2^{32 \times 8}$$, a 64-byte message block $$m^i = (m^i_0, m^i_1, \dots, m_7^i) \in \mathbb{Z}_2^{64 \times 8}$$ and the length $$l^i$$. The $$\texttt{compress}$$ function first initialises an internal state $$\textbf{v} = (v_0, v_1, \dots, v_{15}) \in \mathbb{Z}_2^{32 \times 16}$$ as:

$$
\textbf{v} =
\begin{pmatrix}
v_0 & v_1 & v_2 & v_3 \\
v_4 & v_5 & v_6 & v_7 \\
v_8 & v_9 & v_{10} & v_{11} \\
v_{12} & v_{13} & v_{14} & v_{15} \\
\end{pmatrix}
\leftarrow
\begin{pmatrix}
h_0 & h_1 & h_2 & h_3 \\
h_4 & h_5 & h_6 & h_7 \\
\text{IV}_0 & \text{IV}_1 & \text{IV}_2 & \text{IV}_{3} \\
t_0 \oplus \text{IV}_{4} & t_1 \oplus \text{IV}_{5} & f_0 \oplus  \text{IV}_{6} & f_1 \oplus  \text{IV}_{7} \\
\end{pmatrix}
$$

where $$t_0, t_1, f_0, f_1 \in \mathbb{Z}_2^{32}$$ are counters and finalisation flags respectively. Post this, we iteratively apply the function $$G : (i_0, i_1, i_2, i_3) \in \mathbb{Z}_2^{32 \times 4} \rightarrow (o_0, o_1, o_2, o_3) \in \mathbb{Z}_2^{32 \times 4}$$ on the internal state $$\textbf{v}$$ on 4-tuples:

![Function G is applied on 4-tuples in boxes 0, 1, ..., 7](../.gitbook/assets/blake_matrix.png)

i.e. we execute $$G(0) = G(v_0, v_4, v_8,v_{12})$$ and so on. One round is defined as execution of $$G(0), G(1), \dots, G(7)$$. For Blake2s, we run 10 such rounds, so total number of calls to the function $$G$$ is $$10 \times 8 = 80$$. We define the functions $$G(a,b,c,d \ | \ m^i, r  )$$ as:

$$
\begin{aligned}
a &\leftarrow a + b + m_{\sigma_r[2i]} \\
d &\leftarrow \text{ROTR}^{16}(d \oplus a) \\
c &\leftarrow c+d \\
b &\leftarrow \text{ROTR}^{12}(b \oplus c) \\
a &\leftarrow a + b + m_{\sigma_r[2i+1]} \\
d &\leftarrow \text{ROTR}^{8}(d \oplus a) \\
c &\leftarrow c+d \\
b &\leftarrow \text{ROTR}^{7}(b \oplus c) \\
\end{aligned}
$$

where $$\sigma_r$$ is a pre-defined permutation used in round $$r$$(refer table 5 in the Blake2s paper for the exact round permutations). After these 10 rounds, the last chain value of the $$\texttt{compress}$$ function is computed:

$$
\begin{aligned}
h'_0 &\leftarrow h_0 \oplus  v_0 \oplus v_8 \\
h'_1 &\leftarrow h_1 \oplus  v_1 \oplus v_9 \\
h'_2 &\leftarrow h_2 \oplus  v_2 \oplus v_{10} \\
h'_3 &\leftarrow h_3 \oplus  v_3 \oplus v_{11} \\
h'_4 &\leftarrow h_4 \oplus  v_4 \oplus v_{12} \\
h'_5 &\leftarrow h_5 \oplus  v_5 \oplus v_{13} \\
h'_6 &\leftarrow h_6 \oplus  v_6 \oplus v_{14} \\
h'_7 &\leftarrow h_7 \oplus  v_7 \oplus v_{15}
\end{aligned}
$$

### Implementing Blake2s using Lookup tables (5-bit slices)

Zac has written a [spec](https://hackmd.io/6SPDfLgAQRqdaPXzUlN6-w) on how we could design lookup tables for implementing Blake2s. This implementation uses **5-bit slices** for improved table efficiency.

#### Slice Structure

With 5-bit slices, we decompose a 32-bit value into **7 slices**:

$$
\underbrace{s_6}_{5 \text{ bits}}
\ \underbrace{s_5}_{5 \text{ bits}}
\ \underbrace{s_4}_{5 \text{ bits}}
\ \underbrace{s_3}_{5 \text{ bits}}
\ \underbrace{s_2}_{5 \text{ bits}}
\ \underbrace{s_1}_{5 \text{ bits}}
\ \underbrace{s_0}_{5 \text{ bits}}
$$

where:
- $$s_0$$ through $$s_5$$ each contain 5 bits of the 32-bit value (bits 0-4, 5-9, 10-14, 15-19, 20-24, 25-29)
- $$s_6$$ contains the remaining 2 bits (bits 30-31) plus 3 bits for overflow handling = 5 bits total

The slice boundaries are at bit positions: 0, 5, 10, 15, 20, 25, 30.

#### Rotation Analysis

For the XOR-rotate operations in Blake2s, we need to understand how each rotation interacts with the 5-bit slice boundaries:

$$
\begin{aligned}
u &=
\underbrace{00}_{s_6} \
\underbrace{10011}_{s_5} \
\underbrace{01010}_{s_4} \
\underbrace{11011}_{s_3} \
\underbrace{01011}_{s_2} \
\underbrace{11100}_{s_1} \
\underbrace{10011}_{s_0}
\\
\text{ROTR}^{16}(u) &= \text{bits shift by 16 positions}
\\
\text{ROTR}^{12}(u) &= \text{bits shift by 12 positions}
\\
\text{ROTR}^{8}(u) &= \text{bits shift by 8 positions}
\\
\text{ROTR}^{7}(u) &= \text{bits shift by 7 positions}
\end{aligned}
$$

The key insight is that rotations create boundaries within slices:
- **ROTR^16**: Boundary at bit 16, which is 1 bit into $$s_3$$ (since $$s_3$$ starts at bit 15). Slice $$s_3$$ needs a 1-bit rotation.
- **ROTR^12**: Boundary at bit 12, which is 2 bits into $$s_2$$ (since $$s_2$$ starts at bit 10). Can be derived from XOR table.
- **ROTR^8**: Boundary at bit 8, which is 3 bits into $$s_1$$ (since $$s_1$$ starts at bit 5). Slice $$s_1$$ needs a 3-bit rotation.
- **ROTR^7**: Boundary at bit 7, which is 2 bits into $$s_1$$. Slice $$s_1$$ needs a 2-bit rotation.

#### Output Bit Positions After Rotation

The following table shows where each slice's bits end up after rotation:

| Slice   | $$\text{ROTR}^{16}$$ | $$\text{ROTR}^{12}$$ | $$\text{ROTR}^{8}$$ | $$\text{ROTR}^{7}$$ |
| ------- | -------------------- | -------------------- | ------------------- | ------------------- |
| $$s_0$$ | 16                   | 20                   | 24                  | 25                  |
| $$s_1$$ | 21                   | 25                   | 29/0                | 30/0                |
| $$s_2$$ | 26                   | 30/0                 | 2                   | 3                   |
| $$s_3$$ | 31/0                 | 3                    | 7                   | 8                   |
| $$s_4$$ | 4                    | 8                    | 12                  | 13                  |
| $$s_5$$ | 9                    | 13                   | 17                  | 18                  |
| $$s_6$$ | 14                   | 18                   | 22                  | 23                  |

Notation "x/y" indicates the slice wraps around (some bits go to position x, others to position y).

#### Basic Lookup Tables

We need the following basic tables for 5-bit slice operations: for $(a \oplus b)$

1. $(a \oplus b)$: `BLAKE_XOR_ROTATE0`
2. $\text{ROTR}^{1}(a \oplus b)$: `BLAKE_XOR_ROTATE1`
3. $\text{ROTR}^{2}(a \oplus b)$: `BLAKE_XOR_ROTATE2`
4. $\text{ROTR}^{3}(a \oplus b)$: `BLAKE_XOR_ROTATE3`
5. $(a \oplus b) \mod 4$: `BLAKE_XOR_ROTATE0_SLICE5_MOD4` (for the overflow slice)

Each basic table has size $$2^5 \times 2^5 = 1024$$ entries.

#### Multi-table for ROTR^16

For $$\text{ROTR}^{16}(A \oplus B)$$ where $$A,B \in \mathbb{Z}_2^{32}$$, we use 7 slices with a normalizing factor of $$2^{16}$$:

| Slice   | Basic table id               | Slice size  | Col 1, 2 coefficients | Col 3 coefficients                 |
| ------- | ---------------------------- | ----------- | --------------------- | ---------------------------------- |
| $$s_0$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$1$$                 | $$2^{16}/2^{16} = 1$$              |
| $$s_1$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^5$$               | $$2^{21}/2^{16} = 2^5$$            |
| $$s_2$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{10}$$            | $$2^{26}/2^{16} = 2^{10}$$         |
| $$s_3$$ | `BLAKE_XOR_ROTATE1`          | $$2^5$$     | $$2^{15}$$            | $$1/2^{16} = 2^{-16}$$             |
| $$s_4$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{20}$$            | $$2^{4}/2^{16} = 2^{-12}$$         |
| $$s_5$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{25}$$            | $$2^{9}/2^{16} = 2^{-7}$$          |
| $$s_6$$ | `BLAKE_XOR_ROTATE0_SLICE5_MOD4` | $$2^5$$  | $$2^{30}$$            | $$2^{14}/2^{16} = 2^{-2}$$         |

The slice $$s_3$$ uses `BLAKE_XOR_ROTATE1` because the rotation boundary (bit 16) is 1 bit into that slice.

#### Multi-table for ROTR^8

For $$\text{ROTR}^{8}(A \oplus B)$$, we use a normalizing factor of $$2^{24}$$:

| Slice   | Basic table id               | Slice size  | Col 1, 2 coefficients | Col 3 coefficients                 |
| ------- | ---------------------------- | ----------- | --------------------- | ---------------------------------- |
| $$s_0$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$1$$                 | $$2^{24}/2^{24} = 1$$              |
| $$s_1$$ | `BLAKE_XOR_ROTATE3`          | $$2^5$$     | $$2^5$$               | $$1/2^{24} = 2^{-24}$$             |
| $$s_2$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{10}$$            | $$2^{3}/2^{24} = 2^{-21}$$         |
| $$s_3$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{15}$$            | $$2^{8}/2^{24} = 2^{-16}$$         |
| $$s_4$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{20}$$            | $$2^{13}/2^{24} = 2^{-11}$$        |
| $$s_5$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{25}$$            | $$2^{18}/2^{24} = 2^{-6}$$         |
| $$s_6$$ | `BLAKE_XOR_ROTATE0_SLICE5_MOD4` | $$2^5$$  | $$2^{30}$$            | $$2^{23}/2^{24} = 2^{-1}$$         |

The slice $$s_1$$ uses `BLAKE_XOR_ROTATE3` because the rotation boundary (bit 8) is 3 bits into that slice.

#### Multi-table for ROTR^7

For $$\text{ROTR}^{7}(A \oplus B)$$, we use a normalizing factor of $$2^{25}$$:

| Slice   | Basic table id               | Slice size  | Col 1, 2 coefficients | Col 3 coefficients                 |
| ------- | ---------------------------- | ----------- | --------------------- | ---------------------------------- |
| $$s_0$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$1$$                 | $$2^{25}/2^{25} = 1$$              |
| $$s_1$$ | `BLAKE_XOR_ROTATE2`          | $$2^5$$     | $$2^5$$               | $$1/2^{25} = 2^{-25}$$             |
| $$s_2$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{10}$$            | $$2^{2}/2^{25} = 2^{-23}$$         |
| $$s_3$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{15}$$            | $$2^{7}/2^{25} = 2^{-18}$$         |
| $$s_4$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{20}$$            | $$2^{12}/2^{25} = 2^{-13}$$        |
| $$s_5$$ | `BLAKE_XOR_ROTATE0`          | $$2^5$$     | $$2^{25}$$            | $$2^{17}/2^{25} = 2^{-8}$$         |
| $$s_6$$ | `BLAKE_XOR_ROTATE0_SLICE5_MOD4` | $$2^5$$  | $$2^{30}$$            | $$2^{22}/2^{25} = 2^{-3}$$         |

The slice $$s_1$$ uses `BLAKE_XOR_ROTATE2` because the rotation boundary (bit 7) is 2 bits into that slice.

### Taking care of overflows in Additions

In the function $$G$$, every alternate step is addition involving the state values $$(a,b,c,d)$$ and the messages $$m_i$$. Now, each state value $$v_i, i \in \{0,1,\dots, 15\}$$ is passed into the function $$G$$ twice in a given round. After the first time a state value $$v_i$$ is passed to the function $$G$$, it could have overflow of upto 2 bits. The second time the same state value is passed to the function $$G$$, it gets updated twice - in the first update, we let the overflow increase to 3 bits and in the second, we use the function `add_normalise()` to ensure that our final result is restricted to 32 bits.

This is why $$s_6$$ has 5 bits total: 2 bits for the actual value (bits 30-31) and 3 bits for overflow. The `BLAKE_XOR_ROTATE0_SLICE5_MOD4` table applies a modulo-4 filter to extract only the 2 value bits during XOR operations, ignoring the overflow bits.

P.S. Zac had written a spec initially on the choice of slice sizes for lookup tables in Blake2s, read it [here](https://hackmd.io/6SPDfLgAQRqdaPXzUlN6-w).

### Generating ROTR_12 from XOR-only table

To generate the lookup output of $$\text{ROTR}^{12}$$, we use the normal XOR table over slices $$s_0, \dots, s_6$$ instead of a dedicated rotate table. By multiplying scalars to each of these slices, we can compute $$\text{ROTR}^{12}$$ from XOR tables.

We need to compute:

$$
\text{ROTR}^{12}(u) = 2^{20}s_0 + 2^{25}s_1 + 2^{30}s_2 + 2^{3}s_3 + 2^{8}s_4 + 2^{13}s_5 + 2^{18}s_6
$$

The output of an XOR table for 7 slices (with 5-bit boundaries) looks like:

| slice   | $$\texttt{column\_3\_acc\_values} \ (i.e. \ \  \text{lookup}_{\text{XOR}}[2][:])$$                                           |
| ------- | ---------------------------------------------------------------------------------------------------------------------------- |
| $$s_0$$ | $$\begin{aligned}  s_0 + 2^{5}s_1 + 2^{10} s_{2} + 2^{15}s_3+ 2^{20} s_{4} + 2^{25} s_{5} + 2^{30} s_6 \end{aligned}$$       |
| $$s_1$$ | $$\begin{aligned}  s_1 + 2^5 s_{2} + 2^{10}s_3+ 2^{15} s_{4} + 2^{20} s_{5} + 2^{25} s_6 \end{aligned}$$                     |
| $$s_2$$ | $$\begin{aligned}  s_{2} + 2^{5}s_3+ 2^{10} s_{4} + 2^{15} s_{5} + 2^{20} s_6 \end{aligned}$$                                |
| $$s_3$$ | $$\begin{aligned} s_3+ 2^{5} s_{4} + 2^{10} s_{5} + 2^{15} s_6 \end{aligned}$$                                               |
| $$s_4$$ | $$\begin{aligned} s_{4} + 2^5 s_{5} + 2^{10} s_6 \end{aligned}$$                                                             |
| $$s_5$$ | $$\begin{aligned} s_5 + 2^5 s_6 \end{aligned}$$                                                                              |
| $$s_6$$ | $$s_6$$                                                                                                                      |

Hence, we can write $$\text{ROTR}^{12}$$ in terms of XOR lookup outputs:

$$
\begin{aligned}
\text{ROTR}^{12}(u) &= 2^{20}s_0 + 2^{25}s_1 + \text{(remaining terms starting at } s_2 \text{)} \\
&= \text{lookup}_{\text{XOR}}[2][2] + 2^{20} \left(\text{lookup}_{\text{XOR}}[2][0] - 2^{10}\text{lookup}_{\text{XOR}}[2][2]\right)
\end{aligned}
$$

This allows us to compute ROTR^12 without a dedicated multi-table, saving table space.

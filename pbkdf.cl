
/*
* Hard-coded, implementation needed.
* Use only with express authorization!
* Author:
* Bruno da Silva
* @ipsbruno3
*/

__constant ulong8 SHA512_DEFAULT =
    (ulong8)(0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL,
             0xa54ff53a5f1d36f1UL, 0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
             0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL);
#undef COPY_EIGHT_XOR
#undef COPY_EIGHT
#define COPY_EIGHT(a, b)                                                       \
  (a)[0] = (b)[0], (a)[1] = (b)[1], (a)[2] = (b)[2], (a)[3] = (b)[3],          \
  (a)[4] = (b)[4], (a)[5] = (b)[5], (a)[6] = (b)[6], (a)[7] = (b)[7];

#define COPY_EIGHT_XOR(a, b)                                                   \
  (a)[0] ^= (b)[0];                                                            \
  (a)[1] ^= (b)[1];                                                            \
  (a)[2] ^= (b)[2];                                                            \
  (a)[3] ^= (b)[3];                                                            \
  (a)[4] ^= (b)[4];                                                            \
  (a)[5] ^= (b)[5];                                                            \
  (a)[6] ^= (b)[6];                                                            \
  (a)[7] ^= (b)[7];

__constant ulong8 PBKDF_TRIMN_VEC =
    (ulong8)(0x8000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
             0x0000000000000000UL, 0x0000000000000000UL, 0x0000000000000000UL,
             0x0000000000000000UL, 1536UL);

void pbkdf2_hmac_sha512_long(ulong T[8]) {
  ulong U[8], state[8]; 
  ulong ipad_mid[8];
  ulong opad_mid[8];
   
  // define your inner_data and outer_data here
  // mnemonicLong[0] ^IPAD etc ...

  vstore8(SHA512_DEFAULT, 0, ipad_mid);
  vstore8(SHA512_DEFAULT, 0, opad_mid);
  // Midstate ipad
  sha512_process(inner_data + 0, ipad_mid);
  // Midstate opad
  sha512_process(outer_data + 0, opad_mid);
  // First iteration (full HMAC)
  COPY_EIGHT(state, ipad_mid);
  sha512_process(inner_data + 16, state); // full inner digest
  COPY_EIGHT(outer_data + 16, state); // set outer message = inner digest
  COPY_EIGHT(T, opad_mid);
  sha512_process(outer_data + 16, T);
  COPY_EIGHT(U, T); // U = first outer para próxima iteração
  // vstore8(PBKDF_TRIMN_VEC, 0, inner_data + 24);  // explico logo abaixo porque não fizemos trim no inner
  COPY_EIGHT(inner_data + 8, outer_data); // reutiliza inner_data para liberar outer_data
  for (ushort i = 1; i < 2048; ++i) {
    // Inner: state = ipad_mid + previous U as message
    COPY_EIGHT(inner_data, U);
    COPY_EIGHT(state, ipad_mid);
    sha512_process_inner(inner_data, state);

    // Outer: state = opad_mid + inner digest as message
    COPY_EIGHT(inner_data + 8, state);
    COPY_EIGHT(U, opad_mid);
    sha512_process_inner(inner_data + 8, U);

    // Acumula
    COPY_EIGHT_XOR(T, U);
  }
}

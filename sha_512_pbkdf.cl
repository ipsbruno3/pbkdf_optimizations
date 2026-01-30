


#define INIT_SHA512(a)                                                         \
  (a)[0] = 0x6a09e667f3bcc908UL;                                               \
  (a)[1] = 0xbb67ae8584caa73bUL;                                               \
  (a)[2] = 0x3c6ef372fe94f82bUL;                                               \
  (a)[3] = 0xa54ff53a5f1d36f1UL;                                               \
  (a)[4] = 0x510e527fade682d1UL;                                               \
  (a)[5] = 0x9b05688c2b3e6c1fUL;                                               \
  (a)[6] = 0x1f83d9abfb41bd6bUL;                                               \
  (a)[7] = 0x5be0cd19137e2179UL;

#define rotr64(a, n) (rotate((a), (64ul - n)))

ulong L0(ulong x) {
  return rotr64(x, 1ul) ^ rotr64(x, 8ul) ^ (x >> 7ul);
}

ulong L1(ulong x) {
  return rotr64(x, 19ul) ^ rotr64(x, 61ul) ^ (x >> 6ul);
}

#define SHA512_S0(x) (rotr64(x, 28ul) ^ rotr64(x, 34ul) ^ rotr64(x, 39ul))
#define SHA512_S1(x) (rotr64(x, 14ul) ^ rotr64(x, 18ul) ^ rotr64(x, 41ul))

#define F1(x, y, z) (bitselect(z, y, x))
#define F0(x, y, z) (bitselect(x, y, ((x) ^ (z))))

#define RoR(a, b, c, d, e, f, g, h, x, K)                                      \
  {                                                                            \
    ulong t1 = K + SHA512_S1(e) + F1(e, f, g) + x;                             \
    h += t1;                                                                   \
    d += h, h += SHA512_S0(a) + F0(a, b, c);                                                           \
  }

  __constant ulong PBKDF_TRIMN[]={
    0x8000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 1536UL
  };


#define SCHEDULE()\
  W16 = W17 + L0(W18) + W26 + L1(W31);\
  W17 = W18 + L0(W19) + W27 + L1(W32);\
  W18 = W19 + L0(W20) + W28 + L1(W16);\
  W19 = W20 + L0(W21) + W29 + L1(W17);\
  W20 = W21 + L0(W22) + W30 + L1(W18);\
  W21 = W22 + L0(W23) + W31 + L1(W19);\
  W22 = W23 + L0(W24) + W32 + L1(W20);\
  W23 = W24 + L0(W25) + W16 + L1(W21);\
  W24 = W25 + L0(W26) + W17 + L1(W22);\
  W25 = W26 + L0(W27) + W18 + L1(W23);\
  W26 = W27 + L0(W28) + W19 + L1(W24);\
  W27 = W28 + L0(W29) + W20 + L1(W25);\
  W28 = W29 + L0(W30) + W21 + L1(W26);\
  W29 = W30 + L0(W31) + W22 + L1(W27);\
  W30 = W31 + L0(W32) + W23 + L1(W28);\
  W31 = W32 + L0(W16) + W24 + L1(W29);\
  W32 = W16 + L0(W17) + W25 + L1(W30);

void sha512_process_inner(__private ulong *message, __private ulong *H){
  __private ulong A0 = H[0], A1 = H[1], A2 = H[2], A3 = H[3], A4 = H[4],
                  A5 = H[5], A6 = H[6], A7 = H[7];

  RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[0], 0x428a2f98d728ae22UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[1], 0x7137449123ef65cdUL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[2], 0xb5c0fbcfec4d3b2fUL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[3], 0xe9b5dba58189dbbcUL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[4], 0x3956c25bf348b538UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[5], 0x59f111f1b605d019UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[6], 0x923f82a4af194f9bUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[7], 0xab1c5ed5da6d8118UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, PBKDF_TRIMN[0], 0xd807aa98a3030242UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, PBKDF_TRIMN[1], 0x12835b0145706fbeUL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, PBKDF_TRIMN[2], 0x243185be4ee4b28cUL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, PBKDF_TRIMN[3], 0x550c7dc3d5ffb4e2UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, PBKDF_TRIMN[4], 0x72be5d74f27b896fUL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, PBKDF_TRIMN[5], 0x80deb1fe3b1696b1UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, PBKDF_TRIMN[6], 0x9bdc06a725c71235UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, PBKDF_TRIMN[7], 0xc19bf174cf692694UL);

  __private ulong W16 =
      (message[0] + L0(message[1]) + PBKDF_TRIMN[1] + L1(PBKDF_TRIMN[6]));
  __private ulong W17 =
      (message[1] + L0(message[2]) + PBKDF_TRIMN[2] + L1(PBKDF_TRIMN[7]));
  __private ulong W18 = (message[2] + L0(message[3]) + PBKDF_TRIMN[3] + L1(W16));
  __private ulong W19 = (message[3] + L0(message[4]) + PBKDF_TRIMN[4] + L1(W17));
  __private ulong W20 = (message[4] + L0(message[5]) + PBKDF_TRIMN[5] + L1(W18));
  __private ulong W21 = (message[5] + L0(message[6]) + PBKDF_TRIMN[6] + L1(W19));
  __private ulong W22 = message[6] + L0(message[7]) + PBKDF_TRIMN[7] + L1(W20);
  __private ulong W23 = message[7] + L0(PBKDF_TRIMN[0]) + W16 + L1(W21);
  __private ulong W24 = PBKDF_TRIMN[0] + L0(PBKDF_TRIMN[1]) + W17 + L1(W22);
  __private ulong W25 = PBKDF_TRIMN[1] + L0(PBKDF_TRIMN[2]) + W18 + L1(W23);
  __private ulong W26 = PBKDF_TRIMN[2] + L0(PBKDF_TRIMN[3]) + W19 + L1(W24);
  __private ulong W27 = PBKDF_TRIMN[3] + L0(PBKDF_TRIMN[4]) + W20 + L1(W25);
  __private ulong W28 = PBKDF_TRIMN[4] + L0(PBKDF_TRIMN[5]) + W21 + L1(W26);
  __private ulong W29 = PBKDF_TRIMN[5] + L0(PBKDF_TRIMN[6]) + W22 + L1(W27);
  __private ulong W30 = PBKDF_TRIMN[6] + L0(PBKDF_TRIMN[7]) + W23 + L1(W28);
  __private ulong W31 = PBKDF_TRIMN[7] + L0(W16) + W24 + L1(W29);
  __private ulong W32 = W16 + L0(W17) + W25 + L1(W30);

  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W16, 0xe49b69c19ef14ad2UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W17, 0xefbe4786384f25e3UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W18, 0x0fc19dc68b8cd5b5UL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W19, 0x240ca1cc77ac9c65UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W20, 0x2de92c6f592b0275UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W21, 0x4a7484aa6ea6e483UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W22, 0x5cb0a9dcbd41fbd4UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W23, 0x76f988da831153b5UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W24, 0x983e5152ee66dfabUL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W25, 0xa831c66d2db43210UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W26, 0xb00327c898fb213fUL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W27, 0xbf597fc7beef0ee4UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W28, 0xc6e00bf33da88fc2UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W29, 0xd5a79147930aa725UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W30, 0x06ca6351e003826fUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W31, 0x142929670a0e6e70UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W32, 0x27b70a8546d22ffcUL);
  SCHEDULE();
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W16, 0x2e1b21385c26c926UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W17, 0x4d2c6dfc5ac42aedUL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W18, 0x53380d139d95b3dfUL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W19, 0x650a73548baf63deUL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W20, 0x766a0abb3c77b2a8UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W21, 0x81c2c92e47edaee6UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W22, 0x92722c851482353bUL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W23, 0xa2bfe8a14cf10364UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W24, 0xa81a664bbc423001UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W25, 0xc24b8b70d0f89791UL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W26, 0xc76c51a30654be30UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W27, 0xd192e819d6ef5218UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W28, 0xd69906245565a910UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W29, 0xf40e35855771202aUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W30, 0x106aa07032bbd1b8UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W31, 0x19a4c116b8d2d0c8UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W32, 0x1e376c085141ab53UL);
  SCHEDULE();
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W16, 0x2748774cdf8eeb99UL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W17, 0x34b0bcb5e19b48a8UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W18, 0x391c0cb3c5c95a63UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W19, 0x4ed8aa4ae3418acbUL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W20, 0x5b9cca4f7763e373UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W21, 0x682e6ff3d6b2b8a3UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W22, 0x748f82ee5defb2fcUL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W23, 0x78a5636f43172f60UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W24, 0x84c87814a1f0ab72UL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W25, 0x8cc702081a6439ecUL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W26, 0x90befffa23631e28UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W27, 0xa4506cebde82bde9UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W28, 0xbef9a3f7b2c67915UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W29, 0xc67178f2e372532bUL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W30, 0xca273eceea26619cUL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W31, 0xd186b8c721c0c207UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W32, 0xeada7dd6cde0eb1eUL);

  W16 = W17 + L0(W18) + W26 + L1(W31);
  W17 = W18 + L0(W19) + W27 + L1(W32);
  W18 = W19 + L0(W20) + W28 + L1(W16);
  W19 = W20 + L0(W21) + W29 + L1(W17);
  W20 = W21 + L0(W22) + W30 + L1(W18);
  W21 = W22 + L0(W23) + W31 + L1(W19);
  W22 = W23 + L0(W24) + W32 + L1(W20);
  W23 = W24 + L0(W25) + W16 + L1(W21);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W16, 0xf57d4f7fee6ed178UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W17, 0x06f067aa72176fbaUL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W18, 0x0a637dc5a2c898a6UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W19, 0x113f9804bef90daeUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W20, 0x1b710b35131c471bUL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W21, 0x28db77f523047d84UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W22, 0x32caab7b40c72493UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W23, 0x3c9ebe0a15c9bebcUL);
  W24 = W25 + L0(W26) + W17 + L1(W22);
  W25 = W26 + L0(W27) + W18 + L1(W23);
  W26 = W27 + L0(W28) + W19 + L1(W24);
  W27 = W28 + L0(W29) + W20 + L1(W25);
  W28 = W29 + L0(W30) + W21 + L1(W26);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W24, 0x431d67c49c100d4cUL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W25, 0x4cc5d4becb3e42b6UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W26, 0x597f299cfc657e2aUL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W27, 0x5fcb6fab3ad6faecUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W28, 0x6c44198c4a475817UL);
  H[0] += A0;
  H[1] += A1;
  H[2] += A2;
  H[3] += A3;
  H[4] += A4;
  H[5] += A5;
  H[6] += A6;
  H[7] += A7;
}
void sha512_process(__private ulong *message, __private ulong *H){
  __private ulong A0 = H[0], A1 = H[1], A2 = H[2], A3 = H[3], A4 = H[4],
                  A5 = H[5], A6 = H[6], A7 = H[7];

  RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[0], 0x428a2f98d728ae22UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[1], 0x7137449123ef65cdUL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[2], 0xb5c0fbcfec4d3b2fUL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[3], 0xe9b5dba58189dbbcUL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[4], 0x3956c25bf348b538UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[5], 0x59f111f1b605d019UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[6], 0x923f82a4af194f9bUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[7], 0xab1c5ed5da6d8118UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, message[8], 0xd807aa98a3030242UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, message[9], 0x12835b0145706fbeUL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, message[10], 0x243185be4ee4b28cUL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, message[11], 0x550c7dc3d5ffb4e2UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, message[12], 0x72be5d74f27b896fUL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, message[13], 0x80deb1fe3b1696b1UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, message[14], 0x9bdc06a725c71235UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, message[15], 0xc19bf174cf692694UL);

  __private ulong W16 =
      (message[0] + L0(message[1]) + message[9] + L1(message[14]));
  __private ulong W17 =
      (message[1] + L0(message[2]) + message[10] + L1(message[15]));
  __private ulong W18 = (message[2] + L0(message[3]) + message[11] + L1(W16));
  __private ulong W19 = (message[3] + L0(message[4]) + message[12] + L1(W17));
  __private ulong W20 = (message[4] + L0(message[5]) + message[13] + L1(W18));
  __private ulong W21 = (message[5] + L0(message[6]) + message[14] + L1(W19));
  __private ulong W22 = message[6] + L0(message[7]) + message[15] + L1(W20);
  __private ulong W23 = message[7] + L0(message[8]) + W16 + L1(W21);
  __private ulong W24 = message[8] + L0(message[9]) + W17 + L1(W22);
  __private ulong W25 = message[9] + L0(message[10]) + W18 + L1(W23);
  __private ulong W26 = message[10] + L0(message[11]) + W19 + L1(W24);
  __private ulong W27 = message[11] + L0(message[12]) + W20 + L1(W25);
  __private ulong W28 = message[12] + L0(message[13]) + W21 + L1(W26);
  __private ulong W29 = message[13] + L0(message[14]) + W22 + L1(W27);
  __private ulong W30 = message[14] + L0(message[15]) + W23 + L1(W28);
  __private ulong W31 = message[15] + L0(W16) + W24 + L1(W29);
  __private ulong W32 = W16 + L0(W17) + W25 + L1(W30);

  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W16, 0xe49b69c19ef14ad2UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W17, 0xefbe4786384f25e3UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W18, 0x0fc19dc68b8cd5b5UL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W19, 0x240ca1cc77ac9c65UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W20, 0x2de92c6f592b0275UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W21, 0x4a7484aa6ea6e483UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W22, 0x5cb0a9dcbd41fbd4UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W23, 0x76f988da831153b5UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W24, 0x983e5152ee66dfabUL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W25, 0xa831c66d2db43210UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W26, 0xb00327c898fb213fUL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W27, 0xbf597fc7beef0ee4UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W28, 0xc6e00bf33da88fc2UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W29, 0xd5a79147930aa725UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W30, 0x06ca6351e003826fUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W31, 0x142929670a0e6e70UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W32, 0x27b70a8546d22ffcUL);
  SCHEDULE();
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W16, 0x2e1b21385c26c926UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W17, 0x4d2c6dfc5ac42aedUL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W18, 0x53380d139d95b3dfUL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W19, 0x650a73548baf63deUL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W20, 0x766a0abb3c77b2a8UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W21, 0x81c2c92e47edaee6UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W22, 0x92722c851482353bUL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W23, 0xa2bfe8a14cf10364UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W24, 0xa81a664bbc423001UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W25, 0xc24b8b70d0f89791UL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W26, 0xc76c51a30654be30UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W27, 0xd192e819d6ef5218UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W28, 0xd69906245565a910UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W29, 0xf40e35855771202aUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W30, 0x106aa07032bbd1b8UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W31, 0x19a4c116b8d2d0c8UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W32, 0x1e376c085141ab53UL);
  SCHEDULE();
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W16, 0x2748774cdf8eeb99UL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W17, 0x34b0bcb5e19b48a8UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W18, 0x391c0cb3c5c95a63UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W19, 0x4ed8aa4ae3418acbUL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W20, 0x5b9cca4f7763e373UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W21, 0x682e6ff3d6b2b8a3UL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W22, 0x748f82ee5defb2fcUL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W23, 0x78a5636f43172f60UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W24, 0x84c87814a1f0ab72UL);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W25, 0x8cc702081a6439ecUL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W26, 0x90befffa23631e28UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W27, 0xa4506cebde82bde9UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W28, 0xbef9a3f7b2c67915UL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W29, 0xc67178f2e372532bUL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W30, 0xca273eceea26619cUL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W31, 0xd186b8c721c0c207UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W32, 0xeada7dd6cde0eb1eUL);

  W16 = W17 + L0(W18) + W26 + L1(W31);
  W17 = W18 + L0(W19) + W27 + L1(W32);
  W18 = W19 + L0(W20) + W28 + L1(W16);
  W19 = W20 + L0(W21) + W29 + L1(W17);
  W20 = W21 + L0(W22) + W30 + L1(W18);
  W21 = W22 + L0(W23) + W31 + L1(W19);
  W22 = W23 + L0(W24) + W32 + L1(W20);
  W23 = W24 + L0(W25) + W16 + L1(W21);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W16, 0xf57d4f7fee6ed178UL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W17, 0x06f067aa72176fbaUL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W18, 0x0a637dc5a2c898a6UL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W19, 0x113f9804bef90daeUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W20, 0x1b710b35131c471bUL);
  RoR(A0, A1, A2, A3, A4, A5, A6, A7, W21, 0x28db77f523047d84UL);
  RoR(A7, A0, A1, A2, A3, A4, A5, A6, W22, 0x32caab7b40c72493UL);
  RoR(A6, A7, A0, A1, A2, A3, A4, A5, W23, 0x3c9ebe0a15c9bebcUL);
  W24 = W25 + L0(W26) + W17 + L1(W22);
  W25 = W26 + L0(W27) + W18 + L1(W23);
  W26 = W27 + L0(W28) + W19 + L1(W24);
  W27 = W28 + L0(W29) + W20 + L1(W25);
  W28 = W29 + L0(W30) + W21 + L1(W26);
  RoR(A5, A6, A7, A0, A1, A2, A3, A4, W24, 0x431d67c49c100d4cUL);
  RoR(A4, A5, A6, A7, A0, A1, A2, A3, W25, 0x4cc5d4becb3e42b6UL);
  RoR(A3, A4, A5, A6, A7, A0, A1, A2, W26, 0x597f299cfc657e2aUL);
  RoR(A2, A3, A4, A5, A6, A7, A0, A1, W27, 0x5fcb6fab3ad6faecUL);
  RoR(A1, A2, A3, A4, A5, A6, A7, A0, W28, 0x6c44198c4a475817UL);
  H[0] += A0;
  H[1] += A1;
  H[2] += A2;
  H[3] += A3;
  H[4] += A4;
  H[5] += A5;
  H[6] += A6;
  H[7] += A7;
}
void sha512_hash_two_blocks_message(__private ulong *message, __private  ulong *H) {
  INIT_SHA512(H);
  sha512_process(message, H);
  sha512_process(message + 16, H);
}
#undef F0
#undef F1

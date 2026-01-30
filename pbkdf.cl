
/*
* Hard-coded.
* You need change "INNER_OUTER" if your salt is not "mnemonic"
* P0, P1, P2, P3, P4 represents first 40 bytes from mnemonic
* If you need more, take a look here 
*
* https://github.com/ipsbruno3/bip39_ulong/blob/main/main.cl
*
* Use only brute-force express authorization!
*
* #### Author #####
* Bruno da Silva
* @ipsbruno3
*
*/

#ifndef REPEAT_5
#define REPEAT_5(x) x, x, x, x, x
#endif
#ifndef IPAD
#define IPAD 0x3636363636363636UL
#endif 
#ifndef OPAD
#define OPAD 0x5C5C5C5C5C5C5
#endif 

#define SHA512_DEFAULT \
          0x6a09e667f3bcc908UL,\
          0xbb67ae8584caa73bUL,\
          0x3c6ef372fe94f82bUL,\
          0xa54ff53a5f1d36f1UL,\
          0x510e527fade682d1UL,\
          0x9b05688c2b3e6c1fUL,\
          0x1f83d9abfb41bd6bUL,\
          0x5be0cd19137e2179UL

#ifndef COPY_EIGHT
#define COPY_EIGHT(a, b)                                                       \
  (a)[0] = (b)[0], (a)[1] = (b)[1], (a)[2] = (b)[2], (a)[3] = (b)[3],          \
  (a)[4] = (b)[4], (a)[5] = (b)[5], (a)[6] = (b)[6], (a)[7] = (b)[7];
#endif 

#ifndef COPY_EIGHT_XOR
#define COPY_EIGHT_XOR(a, b)                                                   \
  (a)[0] ^= (b)[0];                                                            \
  (a)[1] ^= (b)[1];                                                            \
  (a)[2] ^= (b)[2];                                                            \
  (a)[3] ^= (b)[3];                                                            \
  (a)[4] ^= (b)[4];                                                            \
  (a)[5] ^= (b)[5];                                                            \
  (a)[6] ^= (b)[6];                                                            \
  (a)[7] ^= (b)[7];
#endif 

// Preste bastante atenção aqui
// INNER_OUTER é uma constante que otimiza o uso de registers
// Essa inicializada com valor 0x6D6E656D6F6E6963UL que representa a string "mnemonic" 
// Ajuste conforme seu caso de uso. Novamente: é hard-coded para otimizar performance
// 0x0000000180000000UL representa o padded do 0x180 como primeiro bloco tem 8 caracteres o segundo bloco 
// O principal ganho aqui é: se "salt" for permanente, como BIP-39 passamos o "salt" já processado
// para dentro da função sha512_process_constant com devido padded e de preferencia em memoria constante
// Isso reduz o uso de registers e melhora a performance geral do kernel porque parte do código é absorvido em tempo de compilação
// Se precisar mudar o salt a cada pbkdf (bip-39 com senha personalizada), deve adaptar a função para processar o salt dinamicamente usando sha_process ao inves de sha_process antes
// Lembre-se de alterar o tamanho em bits 1120UL = 140 bytes.. 128 do primeiro bloco + "mnemonic" = 136 + 4 bytes do padded = 140 byte

__constant ulong INNER_OUTER[16] = {
                               0x6D6E656D6F6E6963UL,
                               0x0000000180000000UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               0UL,
                               1120UL};


static inline void pbkdf2_hmac_sha512_long(__private ulong *mnemLong,__private ulong *T) {
  ulong U[8], state[8]; 
                      
  ulong ipad_mid[8]={SHA512_DEFAULT};
  ulong opad_mid[8]={SHA512_DEFAULT};

  // ATENÇÃO AQUI:
  // se aqui block pega apenas 11 primeiro valores de mnemonic ou seja até 80 bytes
  // se seu bloco fixo for maior ajuste para pegar todo mnemonicLong até 16
  ulong inner_data[16] = {(P0 ^ IPAD),
                               (P1 ^ IPAD),
                               (P2 ^ IPAD),
                               (P3 ^ IPAD),
                               (P4 ^ IPAD),
                               mnemLong[5] ^ IPAD,
                               mnemLong[6] ^ IPAD,
                               mnemLong[7] ^ IPAD,
                               mnemLong[8] ^ IPAD,
                               mnemLong[9] ^ IPAD,
                               mnemLong[10] ^ IPAD,                               
                               REPEAT_5(IPAD)};

  // sha_process o pior caso de uso de register utiliza exatamente 96 registers
  // o pbkdf2 com 2048 iterações, mas dentro do loop usamos diretamente sha_process_inner que usa menos registers
  // isso significa que o kernel consegue rodar com mais warps por SM
  // o ganho de performance é significativo e no loop principal você deve ver picos máximos de uso de 80-88 registers
  sha512_process(inner_data, ipad_mid);
  COPY_EIGHT(state, inner_data);
  #pragma unroll
  for (ushort i = 0; i < 16; ++i) {
    inner_data[i] ^= 0x6A6A6A6A6A6A6A6AUL;
  }
  sha512_process(inner_data, opad_mid);
  COPY_EIGHT(inner_data, state);
  COPY_EIGHT(state, ipad_mid);
  // ATENÇÃO aqui:
  // criado uma constant em SHA que pega parametro aonde message é constante
  // o objetivo é otimizar e reduzir o uso de registers em  tempo real
  // essa parte é não é fixa se precisar mudar deve usar sha_process(var_dinamica, state)
  // se seu inner final é constante, ou seja apenas o salt é fixo, use essa otimização
  // se seu inner varia a cada pbkdf2, adapte para sha_process(inner_data, state)
  sha512_process_constant(INNER_OUTER, state); 
  COPY_EIGHT(U, state); 
  COPY_EIGHT(T, opad_mid);
  sha512_process_inner(U, T);
  COPY_EIGHT(U, T); 
  // atenção aqui ushort vai até 65535 para .. aqui vai precisar mudar para int se quiser interações maiores que este valor
  for (ushort i = 1; i < 2048; ++i) {
    // aqui já temos ipad_min e opad_min sem precisar recalcular todas interações.. não precisa mudar nada
    COPY_EIGHT(inner_data, U);
    COPY_EIGHT(state, ipad_mid);
    // atenção aqui: inner_data é só acessado até 8 elementos os outros são fixos intrinseco da funcao inner.. não precisa mudar nada
    sha512_process_inner(inner_data, state);
    COPY_EIGHT(inner_data + 8, state);
    COPY_EIGHT(U, opad_mid);
    sha512_process_inner(inner_data + 8, U);
    COPY_EIGHT_XOR(T, U);
  }
}


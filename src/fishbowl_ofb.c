#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fishbowlOFBEncrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *key, int bufsize) { 
    FILE *infile, *outfile;
    unsigned char *keyprime[26] = {0};
    int K[key_length];
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char iv[iv_length];
    memset(iv, 0, iv_length);
    wiqa_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    wiqa_kdf(key, strlen(key), keyprime, kdf_iterations);
    // Setup FishBowl
    struct fbstate state;
    memset(state.R, 0, 10*(10*(sizeof(int))));
    memset(state.S, 0, 10*(26*(sizeof(int))));
    memset(state.SI, 0, 10*(26*(sizeof(int))));
    state.rounds = 10;
    state.shift = 3;
    state.blocklen = 20;
    state.halfblock = state.blocklen / 2;
    convertKeytoNum(K, keyprime, key_length);
    genRoundKeys(&state, K, key_length);
    genSBoxes(&state, K, key_length);
    subRoundKeys(&state);
    uint64_t blocks = fsize / bufsize;
    int extrachars = state.blocklen - (fsize % state.blocklen);
    int extra = fsize % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    if (fsize < bufsize) {
        blocks = 1;
    }
    int c = 0;
    int i;
    int b = 0;
    int bytes[20] = {0};
    int left[10] = {0};
    int right[10] = {0};
    unsigned char block[20] = {0};
    convertBlocktoNum(&state, left, right, iv);
    for (i = 0; i < blocks; i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        int bblocks = bufsize / state.blocklen;
        int bextra = bufsize % state.blocklen;
        if (bextra != 0) {
            bblocks += 1;
        }
        if (bufsize < state.blocklen) {
            bblocks = 1;
        }
        c = 0;
        for (b = 0; b < bblocks; b++) {
            for (int x = 0; x < state.blocklen; x++) {
                block[x] = buffer[c+x];
            }
            convertBlocktoNumOFB(&state, bytes, block);
            roundEnc(&state, left, right, state.blocklen);
            ofbEnc(&state, bytes, left, right);

            convertBlocktoCharOFB(&state, block, bytes);
            for (int x = 0; x < state.blocklen; x++) {
                buffer[x+c] = block[x];
            }
            c += state.blocklen;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}

void fishbowlOFBDecrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *key, int bufsize) {
    fsize = fsize - iv_length;
    FILE *infile, *outfile;
    unsigned char *keyprime[26] = {0};
    int K[key_length];
    unsigned char buffer[bufsize];
    memset(buffer, 0, bufsize);
    unsigned char iv[iv_length];
    infile = fopen(infile_name, "rb");
    wiqa_kdf(key, strlen(key), keyprime, kdf_iterations);
    int ss = 0;
    int count = 0;
    struct fbstate state;
    memset(state.R, 0, 10*(10*(sizeof(int))));
    memset(state.S, 0, 10*(26*(sizeof(int))));
    memset(state.SI, 0, 10*(26*(sizeof(int))));
    state.rounds = 10;
    state.shift = 3;
    state.blocklen = 20;
    state.halfblock = state.blocklen / 2;

    int bytes[20] = {0};
    int left[10] = {0};
    int right[10] = {0};
    unsigned char block[20] = {0};
    outfile = fopen(outfile_name, "wb");
    convertKeytoNum(K, keyprime, key_length);
    genRoundKeys(&state, K, key_length);
    genSBoxes(&state, K, key_length);
    subRoundKeys(&state);
    uint64_t blocks = fsize / bufsize;
    int extra = fsize % bufsize;
    if (extra != 0) {
        blocks += 1;
    }
    if (fsize < bufsize) {
        blocks = 1;
    }
    int c = 0;
    int i = 0;
    int b = 0;
    fread(iv, 1, iv_length, infile);
    convertBlocktoNum(&state, left, right, iv);
    for (i = 0; i < blocks; i++) {
        if (i == (blocks - 1) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        c = 0;
        int bblocks = bufsize / state.blocklen;
        int bextra = bufsize % state.blocklen;
        if (bextra != 0) {
            bblocks += 1;
        }
        for (b = 0; b < bblocks; b++) {
            for (int x = 0; x < state.blocklen; x++) {
               block[x] = buffer[c+x];
            }   
            convertBlocktoNumOFB(&state, bytes, block);
            roundEnc(&state, left, right, state.blocklen);
            ofbDec(&state, bytes, left, right);
          
            
            convertBlocktoCharOFB(&state, block, bytes);
            for (int x = 0; x < state.blocklen; x++) {
                buffer[x+c] = block[x];
            }   

            c += state.blocklen;
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}

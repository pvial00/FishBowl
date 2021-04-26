#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wiqa.c"
#include "fishbowl.c"

void fishbowlCBCEncrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *key, int bufsize) { 
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
    int last_left[10] = {0};
    int last_right[10] = {0};
    int left[10] = {0};
    int right[10] = {0};
    unsigned char block[20] = {0};
    //memset(block, 0, state.blocklen*sizeof(unsigned char));
    convertBlocktoNum(&state, last_left, last_right, iv);
    for (i = 0; i < blocks; i++) {
        if ((i == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(&buffer, 1, bufsize, infile);
        if ((i == (blocks - 1)) && (extrachars != 0)) {
            for (int p = 0; p < extrachars; p++) {
                buffer[(bufsize+extrachars-1)-p] = (unsigned char *)(extrachars + 65);
            }
            bufsize = bufsize + extrachars;
        }
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
            convertBlocktoNum(&state, left, right, block);
            cbcEnc(&state, last_left, last_right, left, right);
            roundEnc(&state, left, right, state.blocklen);

            cbcSave(&state, last_left, last_right, left, right);
            convertBlocktoChar(&state, block, left, right);
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

void fishbowlCBCDecrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *key, int bufsize) {
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

    int last_left[10] = {0};
    int last_right[10] = {0};
    int previous_left[10] = {0};
    int previous_right[10] = {0};
    int left[10] = {0};
    int right[10] = {0};
    unsigned char block[20] = {0};
    outfile = fopen(outfile_name, "wb");
    convertKeytoNum(K, keyprime, key_length);
    genRoundKeys(&state, K, key_length);
    genSBoxes(&state, K, key_length);
    genInverseSBoxes(&state);
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
    convertBlocktoNum(&state, previous_left, previous_right, iv);
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
            convertBlocktoNum(&state, left, right, block);
            cbcSave(&state, last_left, last_right, left, right);
            roundDec(&state, left, right, state.blocklen);
         
            cbcDec(&state, previous_left, previous_right, left, right);
          
            convertBlocktoChar(&state, block, left, right);
            for (int x = 0; x < state.blocklen; x++) {
                buffer[x+c] = block[x];
            }   

            cbcSave(&state, previous_left, previous_right, last_left, last_right);
            c += state.blocklen;
        }
        if (i == (blocks - 1)) {
            int padcheck = (buffer[bufsize - 1] - 65);
            int g = bufsize - 1;
            for (int p = 0; p < padcheck; p++) {
                if (((int)buffer[g] - 65) == padcheck) {
                    count += 1;
                }
                g = g - 1;
            }
            if (padcheck == count) {
                bufsize = bufsize - count;
            }
        }
        fwrite(buffer, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);

}

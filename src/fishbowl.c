#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* KryptoMagick FishBowl Cipher [2021]  */

struct fbstate {
    int S[16][26];
    int SI[16][26];
    int R[16][10];
    int shift;
    int rounds;
    int blocklen;
    int halfblock;
};

int C0[26] = {21, 8, 20, 17, 11, 2, 25, 16, 13, 1, 19, 12, 15, 4, 10, 14, 6, 22, 24, 3, 18, 5, 7, 9, 0, 23};
int C1[26] = {5, 12, 1, 11, 0, 2, 22, 18, 10, 14, 25, 13, 7, 23, 17, 3, 15, 4, 19, 6, 9, 21, 24, 8, 16, 20};

void rotate(int *block, int blocklen, int shift) {
    int *tmp;
    for (int x = 0; x < shift; x++) {
        for (int y = 0; y < blocklen - 1; y++) {
            tmp = block[y];
            block[y] = block[modadd(y, 1, blocklen)];
            block[modadd(y, 1, blocklen)] = tmp;
        }
    }
}

void rotateBack(int *block, int blocklen, int shift) {
    int *tmp;
    for (int x = 0; x < shift; x++) {
        for (int y = blocklen - 1; y != 0; y--) {
            tmp = block[y];
            block[y] = block[modadd(y, 1, blocklen)];
            block[modadd(y, 1, blocklen)] = tmp;
        }
    }
}

void roundEnc(struct fbstate * state, int *left, int *right, int blocklen) {
    int *tmp[10] = {0};
    for (int r = 0; r < state->rounds; r++) {
        for (int i = 0; i < state->halfblock; i++) {
            right[i] = modadd(right[i], state->R[r][i], 26);
            left[i] = state->S[i][left[i]];
            left[i] = modadd(left[i], right[i], 26);
            right[i] = modadd(right[i], left[i], 26);
        }
        rotate(right, state->halfblock, state->shift);
        memcpy(tmp, left, state->halfblock);
        memcpy(left, right, state->halfblock);
        memcpy(right, tmp, state->halfblock);
    }
}

void roundDec(struct fbstate * state, int *left, int *right, int blocklen) {
    int *tmp[10] = {0};
    for (int r = (state->rounds - 1); r != -1; r--) {
        memcpy(tmp, left, state->halfblock);
        memcpy(left, right, state->halfblock);
        memcpy(right, tmp, state->halfblock);
        rotateBack(right, state->halfblock, state->shift);
        for (int i = (state->halfblock - 1); i != -1; i--) {
            right[i] = modsub(right[i], left[i], 26);
            left[i] = modsub(left[i], right[i], 26);
            left[i] = state->SI[i][left[i]];
            right[i] = modsub(right[i],  state->R[r][i], 26);
        }
    }
}

void convertBlocktoNum(struct fbstate *state, int * left, int * right, unsigned char *block) {
    int c = 0;
    for (int x = 0; x < state->halfblock; x++) {
        left[x] = char_to_num(block[c]);
        c += 1;
    }
    for (int x = 0; x < state->halfblock; x++) {
        right[x] = char_to_num(block[c]);
        c += 1;
    }
}

void convertBlocktoNumOFB(struct fbstate *state, int * dest, unsigned char *block) {
    for (int x = 0; x < state->blocklen; x++) {
        dest[x] = char_to_num(block[x]);
    }
}


void convertKeytoNum(int * K, unsigned char *key, int keylen) {
    for (int x = 0; x < keylen; x++) {
        K[x] = char_to_num(key[x]);
    }
}

void convertKeytoNum52(int * Ka, int *Kb,  unsigned char *key, int keylen) {
    int c = 0;
    for (int x = 0; x < keylen; x++) {
        Ka[x] = char_to_num(key[c]);
        c += 1;
    }
    for (int x = 0; x < keylen; x++) {
        Kb[x] = char_to_num(key[c]);
        c += 1;
    }
}

void convertBlocktoChar(struct fbstate *state, unsigned char * block, int *left, int *right) {
    int c = 0;
    for (int x = 0; x < state->halfblock; x++) {
        block[c] = num_to_char(left[x]);
        c += 1;
    }
    for (int x = 0; x < state->halfblock; x++) {
        block[c] = num_to_char(right[x]);
        c += 1;
    }
}

void convertBlocktoCharOFB(struct fbstate *state, unsigned char * block, int *source) {
    for (int x = 0; x < state->blocklen; x++) {
        block[x] = num_to_char(source[x]);
    }
}


void cbcEnc(struct fbstate *state, int *last_left, int *last_right, int *left, int *right) {
    for (int x = 0; x < state->halfblock; x++) {
        left[x] = modadd(left[x], last_left[x], 26);
        right[x] = modadd(right[x], last_right[x], 26);
    }
}

void cbcDec(struct fbstate *state, int *last_left, int *last_right, int *left, int *right) {
    for (int x = 0; x < state->halfblock; x++) {
        left[x] = modsub(left[x], last_left[x], 26);
        right[x] = modsub(right[x], last_right[x], 26);
    }
}

void cbcSave(struct fbstate *state, int *last_left, int *last_right, int *left, int *right) {
    memcpy(last_left, left, state->halfblock);
    memcpy(last_right, right, state->halfblock);
}

void ofbEnc(struct fbstate *state, int *block, int *left, int *right) {
    int c = 0;
    for (int x = 0; x < state->halfblock; x++) {
        block[c] = modadd(block[c], left[x], 26);
        c += 1;
    }
    for (int x = 0; x < state->halfblock; x++) {
        block[c] = modadd(block[c], right[x], 26);
        c += 1;
    }
}

void ofbDec(struct fbstate *state, int *block, int *left, int *right) {
    int c = 0;
    for (int x = 0; x < state->halfblock; x++) {
        block[c] = modsub(block[c], left[x], 26);
        c += 1;
    }
    for (int x = 0; x < state->halfblock; x++) {
        block[c] = modsub(block[c], right[x], 26);
        c += 1;
    }
}

void genRoundKeys(struct fbstate *state, unsigned char *key, int keylen) {
    int k[26] = {0};
    int j = 0;
    int output = 0;
    int r = 0;
    int i = 0;
    int c = 0;
    for (c = 0; c < 26; c++) {
        k[c] = C0[c];
    }
    for (c = 0; c < keylen; c++) {
        k[c % 26] = (k[c % 26] + key[c]) % 26;
        j = modadd(j, k[c % 26], 26); }
    c = 0;
    for (r = 0; r < state->rounds; r++) {
        for (i = 0; i < (100 * 26); i++) {
            j = k[j];
            k[j] = modadd(k[c], k[j], 26);
            output = modadd(k[k[j]], k[j], 26);
            k[c] = modadd(k[c], output, 26);
            rotate(k, 26, state->shift);
            c = (c + 1) % 26;
        }
        for (i = 0; i < state->halfblock; i++) {
            j = k[j];
            k[j] = modadd(k[c], k[j], 26);
            output = modadd(k[k[j]], k[j], 26);
            rotate(k, 26, state->shift);
            state->R[r][i] = output;
            c = (c + 1) % 26;
        }
    }
}

void genSBoxes(struct fbstate *state, unsigned char *key, int keylen) {
    int k[26] = {0};
    int j = 0;
    int output = 0;
    int tmp;
    int r = 0;
    int i = 0;
    int c = 0;
    for (r = 0; r < state->rounds; r++) {
        for (i = 0; i < 26; i++) {
            state->S[r][i] = i;
        }
    }
    for (c = 0; c < 26; c++) {
        k[c] = C1[c];
    }
    for (c=0; c < keylen; c++) {
        k[c % 26] = (k[c % 26] + key[c]) % 26;
        j = (j + k[c % 26]) % 26; }
    c = 0;
    for (r = 0; r < state->rounds; r++) {
        for (i = 0; i < (100 * 26); i++) {
            j = k[j];
            k[j] = modadd(k[c], k[j], 26);
            output = modadd(k[k[j]], k[j], 26);
            c = (c + 1) % 26;
        }
        for (i = 0; i < (100 *26); i++) {
            j = k[j];
            k[j] = modadd(k[c], k[j], 26);
            output = modadd(k[k[j]],  k[j], 26);
            rotate(k, 26, state->shift);
            tmp = state->S[r][c];
            state->S[r][c] = state->S[r][output];
            state->S[r][output] = tmp;
            c = (c + 1) % 26;
        }
    }

}

void genInverseSBoxes(struct fbstate *state) {
    int tmp;
    for (int r = 0; r < state->rounds; r++) {
        for (int i = 0; i < 26; i++) {
            tmp = state->S[r][i];
            state->SI[r][tmp] = i;
        }
    }
}

void subRoundKeys(struct fbstate *state) {
    for (int r = 0; r < state->rounds; r++) {
        for (int i = 0; i < state->halfblock; i++) {
            state->R[r][i] = state->S[i][state->R[r][i]];
        }
    }
}

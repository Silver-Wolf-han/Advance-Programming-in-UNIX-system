#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>

#include "libgotoku.h"

static void (*gop_show_fp)() = NULL;
static void (*gop_up_fp)() = NULL;
static void (*gop_down_fp)() = NULL;
static void (*gop_left_fp)() = NULL;
static void (*gop_right_fp)() = NULL;
static void (*gop_fill_0_fp)() = NULL;
static void (*gop_fill_1_fp)() = NULL;
static void (*gop_fill_2_fp)() = NULL;
static void (*gop_fill_3_fp)() = NULL;
static void (*gop_fill_4_fp)() = NULL;
static void (*gop_fill_5_fp)() = NULL;
static void (*gop_fill_6_fp)() = NULL;
static void (*gop_fill_7_fp)() = NULL;
static void (*gop_fill_8_fp)() = NULL;
static void (*gop_fill_9_fp)() = NULL;

static int (*game_init_fp)() = NULL;
static gotoku_t* (*game_load_fp)(const char *path) = NULL;

int local_board[9][9], local_original_board[9][9];
int local_x, local_y;

void local_lib_init(void) __attribute__((constructor));

void local_lib_init(void) {

    game_init_fp = dlsym(RTLD_NEXT, "game_init");
    game_load_fp = dlsym(RTLD_NEXT, "game_load");

    gop_show_fp = dlsym(RTLD_NEXT, "gop_show");
    gop_up_fp = dlsym(RTLD_NEXT, "gop_up");
    gop_down_fp = dlsym(RTLD_NEXT, "gop_down");
    gop_left_fp = dlsym(RTLD_NEXT, "gop_left");
    gop_right_fp = dlsym(RTLD_NEXT, "gop_right");
    gop_fill_0_fp = dlsym(RTLD_NEXT, "gop_fill_0");
    gop_fill_1_fp = dlsym(RTLD_NEXT, "gop_fill_1");
    gop_fill_2_fp = dlsym(RTLD_NEXT, "gop_fill_2");
    gop_fill_3_fp = dlsym(RTLD_NEXT, "gop_fill_3");
    gop_fill_4_fp = dlsym(RTLD_NEXT, "gop_fill_4");
    gop_fill_5_fp = dlsym(RTLD_NEXT, "gop_fill_5");
    gop_fill_6_fp = dlsym(RTLD_NEXT, "gop_fill_6");
    gop_fill_7_fp = dlsym(RTLD_NEXT, "gop_fill_7");
    gop_fill_8_fp = dlsym(RTLD_NEXT, "gop_fill_8");
    gop_fill_9_fp = dlsym(RTLD_NEXT, "gop_fill_9");
    if (!game_init_fp || !game_load_fp || !gop_show_fp || !gop_up_fp || !gop_fill_0_fp){
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
        exit(1);
    }
}

int game_init() {
	printf("UP113_GOT_PUZZLE_CHALLENGE\n");
	return game_init_fp();
}


bool isValid(int x, int y, int ans) {
    for (int i = 0; i < 9; ++i) {
        if (local_board[x][i] == ans || local_board[i][y] == ans || local_board[(x/3)*3+i/3][(y/3)*3+i%3] == ans) {
            return false;
        }
    }
    return true;
}

bool dfs() {
    for (int i = 0; i < 9; ++i) {
        for (int j = 0; j < 9; ++j) {
            if (local_board[i][j] == 0) {
                for (int ans = 1; ans <= 9; ++ans) {
                    if (isValid(i, j, ans)) {
                        local_board[i][j] = ans;
                        if (dfs()) {
                            return true;
                        }
                        local_board[i][j] = 0;
                    }
                }
                return false;
            }
        }
    }
    return true;
}

gotoku_t* game_load(const char *path) {
    gotoku_t* gt = game_load_fp(path);
    for (int i = 0; i < 9; ++i) {
        for (int j = 0; j < 9; ++j) {
            local_board[i][j] = gt->board[i][j];
            local_original_board[i][j] = gt->board[i][j];
        }
    }
    local_x = gt->x;
    local_y = gt->y;
    if (!dfs()) {
        printf("Error, Can not find gotoku solution.\n");
        exit(1);
    }
    return gt;
}

void gop_1() {
    local_x = 0, local_y = 0;
    while(true) {
        if (local_original_board[local_x][local_y] == 0) {
            switch (local_board[local_x][local_y]) {
                case 1:
                    gop_fill_1_fp();
                    break;
                case 2:
                    gop_fill_2_fp();
                    break;
                case 3:
                    gop_fill_3_fp();
                    break;
                case 4:
                    gop_fill_4_fp();
                    break;
                case 5:
                    gop_fill_5_fp();
                    break;
                case 6:
                    gop_fill_6_fp();
                    break;
                case 7:
                    gop_fill_7_fp();
                    break;
                case 8:
                    gop_fill_8_fp();
                    break;
                case 9:
                    gop_fill_9_fp();
                    break;
            }
        }
        if (local_x == 8 && local_y == 8) {
            break;
        } else if (local_x % 2 == 0 && local_y < 8) {
            gop_right_fp();
            ++local_y;
        } else if (local_x % 2 == 0 && local_y == 8) {
            gop_down_fp();
            ++local_x;
        } else if (local_x % 2 != 0 && local_y > 0) {
            gop_left_fp();
            --local_y;
        } else if (local_x % 2 != 0 && local_y == 0) {
            gop_down_fp();
            ++local_x;
        } 
    }
}

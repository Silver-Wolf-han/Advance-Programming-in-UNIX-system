# Lab 3 Gotoku

## 目標

1. Shared Library
2. 覆蓋GOT Entry，簡單來說就是 把Library當中的Function換成自己寫的shared Library

## Todo

:::warning
根據spec，如果是在local執行的話，請先在`/`(根目錄)底下放好一個`/gotoku.txt`
```
 0 0 0 0 8 2 0 0 1
 0 2 0 6 1 0 0 9 8
 1 0 0 0 0 5 0 0 0
 5 0 6 4 9 3 0 0 7
 0 3 7 0 2 8 0 4 6
 8 4 2 1 7 6 0 5 0
 0 0 1 8 0 0 7 6 0
 0 8 0 0 0 0 0 1 3
 0 0 3 2 5 1 0 0 4
```
不然執行時會讀不到檔案，還有之後的lab如果有在local執行檔案通常也都是放在根目錄
:::

1. 怎麼程式編譯成Library? 自己編譯出來的Library怎麼用?
    下面是dummy資料夾裡面的`makefile`
    ```makefile=
    CC = gcc
    CFLAGS = -Wall -g -fPIC

    TARGET = gotoku.local

    LIB_TARGET = libgotoku_dummy.so

    all: $(TARGET) $(LIB_TARGET)

    LIB_OBJS = libgotoku_dummy.o

    $(LIB_TARGET): $(LIB_OBJS)
        $(CC) -shared -o $(LIB_TARGET) $(LIB_OBJS)

    libgotoku_dummy.o: libgotoku_dummy.c libgotoku.h
        $(CC) $(CFLAGS) -c libgotoku_dummy.c

    OBJS = gotoku.o

    $(TARGET): $(OBJS) $(LIB_TARGET)
        $(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -L. -lgotoku_dummy

    gotoku.o: gotoku.c libgotoku.h
        $(CC) $(CFLAGS) -c gotoku.c

    clean:
        rm -f $(TARGET) $(OBJS) $(LIB_TARGET) $(LIB_OBJS) libgotoku_dummy.so libgotoku.so *.o

    .PHONY: clean

    run_dummy:
        LD_LIBRARY_PATH=. ./gotoku.local

    preload:
        LD_PRELOAD=./libgotoku.so LD_LIBRARY_PATH=. ./gotoku.local
    ```
    這是第一題(10%)的makefile 看起來很可怕 
    總共做的事情三件
    1. 編譯出一個shared object檔 (就是library), `libgotoku_dummy.so`
    2. 編譯出一個執行檔案，要link上面的object檔, `gotoku.local`
    3. 執行`gotoku.local`的時候link上面的object檔

    下面是順序
    ```makefile
    gcc -Wall -g -fPIC -c libgotoku_dummy.c
    # 會冒出 libgotoku_dummy.o 就是把.c編譯成.o檔而已
    gcc -shared -o libgotoku_dummy.so libgotoku_dummy.o
    # 會冒出 libgotoku_dummy.so 就是把.o編譯成.so檔而已
    gcc -Wall -g -fPIC -c gotoku.c
    # 會冒出 gotoku.o 就是把.c編譯成.o檔而已
    gcc -Wall -g -fPIC -o gotoku.local gotoku.o -L. -lgotolu_dummy
    # 會冒出 gotoku.local 這是把gotoku.o編譯成執行檔, 而且 要dynamic link library (gotoku_dummy.so), 他的路徑在當前目錄下(.)
    
    ```
    總共兩種東西
    1. library (`.c`->`.o`->`.so`) 這個東西不是拿來執行的 是拿來讓別人link的
    2. 執行檔 (`.c`->`.o`->`exe`) 拿來執行的 如果有要用到別人的library要link進來

2. shared object (`.so`, 就是library) 要寫什麼?
    1. 先看dummy資料夾下面的 `libgotoku_dummy.c` 這個是原本的library 我們的目標就是要取代這個library
    2. 取代這個東西之前，裡面的東西是可以廢物再利用的，可以用`dlsym()`來撈到原本的library當中的名字 就可以利用裡面的function了
    3. 2-A (10%) 的部分，規定解出數獨就好 沒有任何限制 這裡的做法(`local_lib_modify_gop`資料夾)事就直接把修該`gop_1()`這個function的內容。
        3-1. 用`lib_constructor`來先找到2.的東西
        3-2. `game_init`
        3-3. `game_load` 同時dfs解數獨
        3-4. 直接重寫一個`gop_1()`把解完的數值解上去(概念上就是function overwrite)
        
    那因為執行時我們要link的library是新寫的library，而不是原本的dummy 所以執行時
    ```bash
    LD_PRELOAD=./libgotoku.so LD_LIBRARY_PATH=. ./gotoku.local
    # 設定兩個環境變數，前面是哪個.so 中間library的路徑，最後是執行檔
    ```
    
3. 那2-B(10%)呢? 資料夾`local_lib`
    多了很多限制 但其實我的2-A只有違反第三點:Your solver an only call the `gop_*` functions to walk in the puzzle, or modify the GOT table
    反正就是`gop_*`不能改 然後我上面改了`gop_1`
    所以這個部分就是進入下一個目標**modify the GOT table**
    
    Spec當中有給一段python code(`get_got.py`)，這段code就是把`gotoku.local`裡面的function 相對addr撈出來後存到`got.txt`當中，所以這裡就可以直接讀檔把`gop_*`的相對addr撈出來
    
    接著就只要在`get_load`的時候把這些function addr換成我們希望他做的事情就好(把動作的function pointer填進去) 裡面看起來跟上一個步驟的`gop_1`很像 只是前一個步驟我是直接call function最後就是直接覆蓋addr
    
4. 那關於remote(6. 30%)的部分? 資料夾`remote`
    remote做的事情是我們編好自己的library之後 傳給server 讓server link我們的library後執行。
    
    不過我們並不會事先知道server上的`gop_*` addr 所以助教有我們`server`正在執行的binary就用這個東西就可以直接得到`gop_*`的addr了 這些addr就直接hard code在程式裡面送上去即可
    
3 4 5步驟的分數 應該就是輸出而已

6 後面有一大串內容，那些應該只是驗證而已，不是很重要
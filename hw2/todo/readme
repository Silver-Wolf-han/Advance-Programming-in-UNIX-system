# Homework 2

## 目標

練習`ptrace`這個syscall，透過`ptrace`設計一個instruction-level debugger

下面是我所參考的課程範例，有下載課程範例應該都可以找到

1. [autodbg.cpp](https://github.com/chunying/up-inclass/blob/master/ptrace/autodbg.cpp)
    主要骨幹是拿這個改的 這裡包含強制在某個地方插入`0xcc` 修該某個buffer的值 (我印象中是這樣 詳細可以確認課程錄影或投影片)

2. [ptools.cpp](https://github.com/chunying/up-inclass/blob/master/ptrace/ptools.cpp), [ptools.h](https://github.com/chunying/up-inclass/blob/master/ptrace/ptools.h)
    這兩個是`autodbg.cpp`所需要的 主要是拿來讀child process的memory segment ||我動都沒有動直接拿來用||

3. [syscall.c](https://github.com/chunying/up-inclass/blob/master/ptrace/syscall1.c)
    主要拿來參考`syscall`這個instruction怎麼寫


## todo

### 整體流程
1. 創 child process 執行要被debug的程式 (from `autodbg.cpp`)
2. 用 `auxv` 來找到 Entry Point
3. 用 `ptools.h` 來找到 base addr
4. 在 `Entry Point` 插入一個 break point 編號 -1
5. 下 `ptrace(CONT)` 會停在 step 4. 的 break point
6. 依照各個指令做事 (`exeSDBcommand()`)
    6-1. 不會改變control flow的命令 `return 0`
        把該做的事情做完 會在`sdb.cpp:364`重複
        
    6-2. `"si"` 
        沒有踩到break point -> `return 1`
        踩到break point -> `return 2`
    
    6-3. `"cont"`
        `return 1`
    
    6-4. `"syscall"`
        踩到syscall -> `return 0`
        踩到break point -> `return 2`
        
|`return`| 意義 | 範例 |
|:--:|:--:|:--:|
| 0 | 不需要確認狀態<br>1. 沒有動到control flow<br>2.`ptrace(SYSCALL)` 遇到 `syscall` | 1. `info`, `patch`, `break` 等<br>2. 特例 會直接把要處理的處理完|
| 1 | 需要`waitpid`確認狀態<br>也需要繼續檢查是否踩到break point | 1. `cont`<br>2.沒踩到break point的`si` |
| 2 | 已經用`waitpid`檢查過狀態<br>但還需要檢查是否有踩到break point | 1. 踩到break point的`si`和`syscall` |

(這些是我自己定義的 想要改可以亂改)

接下來會講break point怎麼處理 這樣就可以知道上面為什麼要這樣分了

### break point

1. 插入 break point 就把 `0xcc` 取代 原本的byte 原本的byte記錄在struct當中
2. 遇到 break point 的情況
    2-1. 真的踩到了 (執行到`0xcc`後 被停下來)

    怎麼判斷是這種情況? 檢查一下`regs.rip-1`是不是break point
    ```
    0x100: 11 22
    0x102: 11 22 如果這裡有一個break point
    實際情況
    0x102: cc 22 # regs.rip-1 = 0x102
    ```

    2-2. 還沒踩到 但現在的`regs.rip`是break point

    執行完`0x100`的command
    ```
    0x100: 11 22
    0x102: 11 22 <- break point
    實際情況
    0x102: cc 22 # regs.rip = 0x102
    ```
    
    第一種情況先把`rip--` (`0xcc`長度1) 變成第二種

3. 遇到 break point 怎麼處理?
    3-1. 標記這個break point目前是被踩到的狀態(變數`hit`)
    3-2. 先不要recovery(`0xcc`->`0x11`)
    等到需要control flow有改變時(`si`, `cont`, `syscall`)，透過`recovery_oneStep_restore(pid_t)`來處理
    
    3-3. 怎麼處理呢 ~~看那個function名稱應該很好理解~~
        3-3-1. 把 break point recovery (`0xcc`->`0x11`)
        3-3-2. `ptrace(SINGLE_STEP)`把break point走調
        3-3-3. 把 break point restore (`0x11`->`0xcc`)
    
    這樣就可以保證break point繼續發會作用了
    
    因為3-3-2.做完之後 需要`waitpid`來確認狀態才可以繼續做 之後就不可以在遇到外側的`waitpid`了 所以才需要return 2
    
    同理 `syscall`，也是需要`waitpid`來確認情況，看有沒有踩到break point來決定要`return 0`(沒踩到 直接把syscall該做的做完)還是`return 2`(踩到break point) 反正不能`return 1`

### disassemble
只有兩個地方要輸出
1. 確認完 break point 之後
2. syscall

其實這裡只要看spec規範很明確 只要控制流程回到我們手上

### poke byte
```cpp
unsign char poke_byte(pid_t child, unsign long addr, unsign char byte);
```
這個function是如果有需要對byte做任何修改時
舉凡`patch`，插入break point，break point recovery 通通都是call這個function

依照一個word一個word(addr結尾一定是8 or 0)作對齊後填入 (所以多算offset)
因為這樣才有辦法跟memory segement對齊 只要填入一次就可以判斷是否再可寫區域內

如果再`ptrace(PEEK_TEXT,addr)`失敗之後 `return (unsign char)0` 之後搭配`error`確認失敗，如果成功填入，救回傳原本的byte

### DEMO問題

大部分應該上面都有提到了
唯一一個問題是 怎麼面對dynamic link的程式(public example 1-2)
我只能說 我原本引用的`autodbg.cpp`就可以面對了 我幾乎沒有做什麼額外處理?
助教是覺得很奇怪 居然不用處理? 但也放我過了
後來我回去想了一下 我覺得原因可能是因為`autodbg.cpp`是在child process使用`ptrace(TRACE_ME)`吧? 這樣會等到程式跑起來才trace? 如此一來我讀mmap就會讀到真的memory?

### 某個失敗的流程
```
遇到break point
馬上復原
之後處理完control flow後再把break piont存回去
```
這個流程遇到break point插入`jump`類的command時會非常麻煩 因為很難記得那個break ponit要怎麼存回去 (應該還是可以 可是程式就會變得很攏長)
而且還需要在很多地方獨立判斷要不要輸出 (程式變攏長)
這個錯誤的流程讓我通過所有public但是hidden出來只過了一個||順帶一提 這個錯誤的流程可以通過我修課前一年的所有hidden||我用的這個破爛流程 在三小時之內只補好了一個hidden test 所以最後第一次demo時只拿了70 回去之後才重新思索整個流程
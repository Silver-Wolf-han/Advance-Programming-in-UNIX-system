# Homework 1

## 目標

看起來是這屆助教自己出的全新作業

嗯 這個作業光講解就講了一個多小時 最好是錄影+錄音下來 才會比較了解作業在做什麼
還有這次作業應該是discord群組討論最熱烈的一次，而且有時候助教會把一些Hint或公告的內容放在那邊而沒有更新到spec上 如果我有翻到什麼比較重要的再放到這裡

本質上是要實現一篇論文zopline，其核心概念為透過把`syscall`換成`call rax`來對`syscall`的行為做一些修改 而這次作業做的修該行為大概是做一些logger

另外 這個作業中大量使用debugger(一般情況下是用`gdb` 但這次作業因為涉及大量組合語言與stack內容的操作 所以助教一直宣傳使用另一個`pwndbg` 後者的好處大概是每一步列出stack register stack backtrace等資訊 可以不用像`gdb`一樣一直下指令) 至於這次作業debug的方式 助教在spec的Hints有提供一個範例


## todo

### Part 1
這個部分有spec的 step-by-step guide，就是要復刻zopline論文當中的做法

#### ex1
spec大概都講得很清楚
1. 用`mmap`要記憶體
2. 0x0 (0) ~ 0x199 (511) 填入 `NOP (0x90)`
3. 把要處理的code放到0x200 ~ ?

這一步只是要測試如果`call rax`執行下去後 跳到0x0 ~ 0x199後的邏輯行為會成立
就把`write(STDOUT, "Hello from trampoline!", 23)`
轉成組合語言 然後再轉成byte code

#### ex2
是最複雜的一步 zopline論文的核心

這些會寫一些我當初遇到的困難點

1. 流程到底是怎樣?
    當初看spec的時候 不是很懂整個流程是怎樣 只知道會有 C->assemble 和 assemble -> C 的轉換
    那實際流程是下列
    1. 依照ex1 `syscall` 換成 `call rax` 後, 跳到 `0x0 ~ 0x199` 之間 看syscall number
    2. 因為這段填滿`NOP(0x90)` 所以會`rip` program counter 會一直滑 到 `0x200` 的位置
    3. `0x200` 在 ex1 是放 `write(STDOUT, "Hello from trampoline!", 23)` 但這裡現在要改成 跳到我們想要額外處理的程式 (這個額外處理程式是組合語言 `void trampoline()`)
    4. 需要額外處理甚麼事情? 要改syscall行為 用C比較好寫
        這裡是assemble `void trampoline()` -> C (`int handler()`) 的地方
    5. 改完syscall行為後 要回去執行syscall 用組合語言
        這裡是C (`int handler()`) -> assemble (`void __raw_asm()`) 的地方
    
    那 C function argument 和 syscall argument 的差異 可以看spec的 Hint 4
    
    下面是用`rip`的角度來看
    ```
    0x原本位置: call rax (原本的syscall 假設是syscall編號是0)
    0x000000: NOP
    ...
    0x000199: Nop
    # 下面是要跳到void trampoline()的程式 trampline的程式要執行的時候另外算
    0x000200: movabs [64-bit addr (8-byte)],%r11
    0x00020a: jmp    %r11
    # 跳到trampoline()
    0xtrampo: mov %r10, %rcx       # 依照hint把參數塞好
    0xtrampo: push %rsp            # 下面這三行是一組的 目標是為了讓stack addr對齊16byte
    0xtrampo: push (%rsp)          # 理論上這是ex3才需要做的事情
    0xtrampo: andq $-16, %rsp
    0xtrampo: push %rax            # 參考handler參數 第七個參數要放stack 同時確定對齊所以放兩次
    0xtrampo: push %rax
    0xtrampo: call handler
    # 跳去做 handler
    # 而handler最後call了這個trigger_syscall他是定義在組合語言裡面的 不過用extern擴展到C的format
    trigger_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    # 跳去 trigger_syscall:
    0xtrigge: mov 8(%rsp), %rax    # 因為stack最上面會是return addr 所以第二個才是前面push %rax放進去的參數
    0xtrigge: mov %rcx,  %r10      # 同樣依照hint
    0xtrigge: syscall
    0xtrigge: ret
    # return 回 handler
    return trigger_syscall(rdi, rsi, rdx, r10, r8, r9, rax); #tigger已經做完了
    # handler return 回 trampoline()
    0xtrampo: add $16, %rsp        # 0xtramp有兩個push %rax 把他們殺掉
    0xtrampo: movq 8(%rsp), %rsp   # 對標隊齊的那三行
    # 接著到這裡 stack最上面就會是第一行原本位置call rax時 跟著push進來的return addr了
    # 就可以回去做原本的事情了
    ```

2. 怎麼把`syscall` 換成 `call rax` ?
    要用到dissable工具 上課是教||提到五秒||`capstone` 就是一個library，稍微查一下怎麼使用應該沒有很困難
    找到哪裡是`syscall`知道就直接用byte code改寫成`call rax`就好了
    
    這裡還有兩點要注意
    1. rewrite時 `ex2.c:113` 這裡有判斷 如果是`trigger_syscall`就不要rewrite 這個不能rewrite 否則就會一直call rax -> trigger_syscall被換成 call rax -> call rax -> call rax，會沒有辦法做syscall
    2. spec中有說忽略`vsyscall` 這個memory segment 我原先的寫法是`ex2.c:143` 這個寫法會在hidden 1的側資出錯 原因是執行檔就叫`vsycall` 所以我改成`ex3.c:182`的寫法||恩 超爛||
    

#### ex3

如果 ex2 的內容都了解的話 ex3 要多增加的內容沒有很可怕 ||只是新加入的內容很有可能導致ex2的部分崩壞而已|| 這個部分要多加內容是 我們想要在前面的C handler function做其他事情(向輸出之類的) 可是因為rewrite syscall的關係 就必須透過額外的方法來避免我們想要用的library被syscall rewrite 最後導致`for(;;);` 這個額外的方法spec也有講了 這裡就不贅述

下面就講說 加上ex3以後的範例後 為什麼assemble和handler會變成那樣?

1. handler 前面多了一大塊東西?
    參考Spec Hint 5 當中的連結 這是zopline論文原文當中處理`clone`和`clone3`的方式，基本上就是整塊複製貼上
    但有一點需要注意，zopline原文論文當中`retptr`這個變數是他的handler直接傳進來的參數，但因為spec有限定c handler的格式，所以我們是沒有這個變數可以用的
    那要怎麼取得這個變數呢?
    `clone`和`clone3`就是在做創造child process(像`fork()`) 而這個變數就是要讓複製出來的process知道他應該他的return addr=>也就是說這個數字和parent process的return addr要一樣，也就是`call rax`在跳進`0x0`~`0x1ff`之間時，跟著被push到stack的那個數字。
    ||所以我的做法非常沒有道德，直接開一個global變數來記得這個數字||參考`ex3.c:52~53`行，(根據discord討論的結果)應該是要去推算目前stack的狀態來拿到這個數字。
    還有最後一點 這裡的寫法似乎出乎助教意料(應該是只有我這樣寫)，所以當我分享我的方法給我的同學時，導致我的同學在補demo時遭到助教窮追某打，最後追問 為什麼是`push 8(rsp); pop retptr(rsp)` 為什麼不是`push rsp`? 此時rsp是什麼?
    最後就是直接開debugger出來看走到那一步的時候stack的狀態 結果發現，在真正執行`void trampoline()`之前 有一個奇怪的指令(具體甚麼我忘記了)把當前`rbp`扔進stack了，而這是C function自己本身就會做的事情。

2. 組合語言?
    總共多了兩段
    1. 一開始
        ```
        // workaround from TA for vfork
        " cmp $0x3a, %rax    \t\n"
        " jne asm_start      \t\n"
        " pop %rsi           \t\n"
        " pop %rsi           \t\n"
        " syscall            \t\n"
        " push %rsi          \t\n"
        " ret                \t\n"

        " asm_start:         \t\n"
        ```
        這裡註解直接有寫了 如果遇到`vfork()`這個syscall就直接跳過 而且這是助教在discord給的workflow 就照貼上 (同時需要注意這個syscall我們也不希望蓋掉 所以binary rewrite時也要跳過這個syscall
    2. 後半段 這裡比較單純 就是spec當中的Step 2 中間的`Updated on Apr. 16`
        有許多register狀態是要保存好的 所以就call syscall前先扔進stack之後再把從stack拿回來。同時注意對齊。

### Part 2

這個部分應該沒什麼好說的 這是整個作業最舒壓的部分 就是依照example把該輸出的內容輸出出來就好了 ~~本身是很舒壓沒錯 但是可能會有這個側資導致part1崩潰的情形 目前我是把前面的部分都先講解完 然而實際情況是寫這個部分可能需要回去把part1再調整好~~

整個`logger.c`的範例可以參考spec step3 當中的 The following is a sample implementation of a hook library:
那段程式碼
就是把`fprintf`的布分改成spec要求的logger形式即可

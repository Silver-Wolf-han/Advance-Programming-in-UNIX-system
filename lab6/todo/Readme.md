# lab6

## 目標

和lab5很像 都是要想辦法撈到server上正常情況下撈不到的東西 只是lab5是用race condition 這裡是用buffer overflow

每一題要做的事情都是
1. 打開`/FLAG`
    `fd = open("/FLAG")`
2. 把`/FLAG`的內容讀出來
    `read(fd, buf, buf_size)`
3. 把讀到的內容輸出到`stdout`
    `write(1, buf, buf_size)`
4. 結束程式
    `exit(0)`

另外 這裡的fd一定是3 (from discord) 因為是第一個打開的檔案

## todo

這次作業推薦用pwndbg看stack比較方便 
另外怎麼debug?
執行腳本時給個參數`local` 之後印出pid 然後用attach pid的方式來debug

### 1
看server code很單純，把寫的組合語言送出去就好，會直接執行

前27行都是給好的範例腳本
我們要寫得基本上就是
asm_code 變數裡變的東西
然後把它用62行轉乘byte code後送出去
接著收東西就好了

總共四個`syscall` 每一個都是對應以上的每個動作
有幾行是多寫的移動rsp 那個不重要
基本上不是填參數的都可以殺掉試看看
`"/FLAG"`我是填在35~38行 就放在stack裡面


### 2

組合語言的部分應該一模一樣
現在的問題是沒辦法執行程式碼 所以要用Buffer Overflow來執行程式碼
看80行call `task()` 這個function會讓我們輸入
而funciton他read的長度(256)超過他變數給(40)
所以我們可以送東西來覆蓋結果
```

| ...其他東西       | <-rsp
| buf3             |
| ... 其他東西      |
| buf2             |
| ... 其他東西      |
| buf1             |
| ...其他東西       |
| task return addr | (理論上就是81行的位置)
```
目標就是把task return addr換成msg的位置(msg會送和第一題一樣的程式碼)
所以我們要想辦法把那個超過長度來蓋掉task return addr

下面的60行，我先送56個A (送幾個是要考gdb來看的)
```
| ...其他東西       | <-rsp
| buf1             |
| ... 其他東西      |
| buf2             |
| ... 其他東西      |
| buf3 (AAAA       | (56個A)
| AAAAAAAAAA       | 
| task return addr | (理論上就是81行的位置)
```
接著62行有一個收9+8\*7到最後一行(9是他的輸出，8\*7是我送的)
他會連task return addr是多少一起傳回來
\+ 0xe5587是從return addr去算msg addr(server code的12行)是多少 用gdb看
61 行 接著又送了8 * 13 個A 加上上面算出來的msg addr
```
| ...其他東西       | <-rsp
| buf3             |
| ... 其他東西      |
| buf2 (AAAA       | (8*13個A)
| AAAAAAAAAA       |
| buf1 (AAAA       | 
| AAAAAAAAAA       | 
| msg addr         | (被換掉了)
```
接下來第三個不重要
最後把asm_code送到msg裡面就好了


### 3

理論上第二題一模一樣，只是有開canary，所以stack情況會變成
||我不確定為甚麼第二題和第三題buf方向是反的 但這是gdb看到的||
```

| ...其他東西       | <-rsp
| buf1             |
| ... 其他東西      |
| buf2             |
| ... 其他東西      |
| buf3             |
| ...其他東西       |
| canary           |
| task return addr | (理論上就是81行的位置)
```
那就是一個保護裝置，避免出現越界
要做的事情就是覆蓋掉return addr的同時，還需要把canary保存並存回去

所以流程變成
把 canary記下來
```
| ...其他東西       | <-rsp
| buf1 (AAAA)      | 送這裡
| AAAAAAAAAA       |
| buf2 (AAAA)      |
| AAAAAAAAAA       |
| buf3 (AAAA)      |
| AAAAAAAAAA       |
| canary           |
| task return addr | (理論上就是81行的位置)
```
把 return addr記下來算msg addr
```
| ...其他東西       | <-rsp
| buf1 (AAAA)      | 
| AAAAAAAAAA       |
| buf2 (AAAA)      | 送這裡
| AAAAAAAAAA       |
| buf3 (AAAA)      |
| AAAAAAAAAA       |
| AAAAAAAAAA       | (蓋掉了
| task return addr | (理論上就是81行的位置)
```
把 canary + msg addr存回去
```
| ...其他東西       | <-rsp
| buf1 (AAAA)      | 
| AAAAAAAAAA       |
| buf2 (AAAA)      | 
| AAAAAAAAAA       |
| buf3 (AAAA)      | 送這裡
| AAAAAAAAAA       |
| canary           | (蓋掉了
| msg return addr  | 
```
把 asm_code送回去


### 4

基本上沒有msg變數可以操作了，所以目標變成
```
| ...其他東西       | <-rsp
| buf1             |
| ... 其他東西      |
| buf2             |
| ... 其他東西      |
| buf3             |
| ...其他東西       |
| canary           |
| task return addr | (理論上就是81行的位置)
```

```
| ...其他東西       | <-rsp
| buf1             |
| ... 其他東西      |
| buf2             |
| ... 其他東西      |
| buf3             |
| ...其他東西       |
| canary           |
| ROP-程式碼        |
```
用ROP來達到特定組合語言的效果 (可以看spec說明或Hint)
拿來放`/FLAG`的空間 和讀到的東西 就直接換成上面的buf 

至於base addr和 return addr怎麼找?
用`objdump`來看哪裡有call `<task>`

想要特定功能的ROP 可以用spec裡面的指令+`grep`來找
只有一組`syscall; ret;`這組 我是透過pwndbg找到的

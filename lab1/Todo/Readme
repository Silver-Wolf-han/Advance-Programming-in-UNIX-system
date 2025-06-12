# Lab1 docker & pwntool


## 目標

這個Lab要做的事情
1. 裝好環境
2. 熟悉pwntool

中間有冒出一個pow(proof-of-work)，可以直接忽略這個東西，這只是一種驗證手段而已，就套他給好的code就好。

裝環境就選擇喜歡的裝吧 大部分的人應該是裝**WSL** 我是用**VMware + Ubuntu 24.04** 應該都可以 (還有從後面的Lab看起來 使用MacOS完成作業會有很多困擾 所以盡量弄一台 Linux的機器吧)

pwntool 可以直接想像成一種可以幫助你完成傳輸的腳本套件

主要會用到個功能就三個類型
1. 連線 以下兩個本質是一樣的 只是在local端要測試比較方便
    remote
    ```py
    conn = remote("ip", port)
    conn.close()
    ```
    local
    ```py
    r = process("command or exe", shell = False)
    r.close()
    ```
2. 送東西 send開頭
    ```py
    conn.sendline("A")
    ```
4. 收東西 recv開頭
    ```py
    one_line = conn.recvline()
    ```

反正就是一個拿來跟要連線目標溝通的套件而已，怎麼送可以直接查library ||或問ChatGPT||

## Todo

3. ***simple HTTP challenge***
    把那個網址的內容撈下來輸出而已
    送一個HTTP Request過去就好

4. 一個遊戲機
    用來熟悉pwntools 透過觀察`guess.dist.py`(server行為)來決定怎麼和server互動(像是先收什麼訊息 收到訊息怎麼恢復等)，應該可以不用實際解出遊戲，就可以完成互動就好
    ||解遊戲叫ChatGPT寫||
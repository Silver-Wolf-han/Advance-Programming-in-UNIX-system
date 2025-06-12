# Lab 2 have fun with kernel module

要做一個Kernel Module出來
比較複雜，前面多了一個pre-lab練習 基本上是在練習
1. 怎麼開一個kernel出來
2. 怎麼把我們的程式丟進去kernel裡面

||反正很複雜 我也沒有理解||

## 目標

kernel module 包含

1. `write` 輸入kernel
2. `read` kernel輸出
3. `ioctl` 控制io

依照spec做出這些東西

## Todo

`312552056_lab02/`底下的是我寫的程式，在`todo`裡面有複製一份，`todo`裡面的其他程式都是按`make`之後會自己冒出來的東西

`archive_into_kernel.sh`是我自己寫的腳本 編譯完程式後基本上只有`.ko`檔是等一下要跟著`qemu.sh`一起包進去kernel裡面

`cryptomod.c`
應該可以看註解，除了spec要求的function應該其他都和先給好的程式一樣

需要特別注意的應該是`DEC`+`ADV` 這種情況在收到final之前都必須留一個block在buffer當中，否則會沒有辦法解padding

整個作業最麻煩的應該是學會把kernel module開起來吧

||對multi thread的側資 理論上是把mutex加好加滿就好，可是在我的程式裡如果沒有在function開頭結尾+`printk`的話會multi thread會出問題 所以這應該是有bug||

||另外 因為~~年代久遠~~，實在沒有很記得當初寫的時候遇到什麼問題 如果我詳細了解kernel module之後再想看看有沒有什麼可以補充||
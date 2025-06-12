# Lab5

## 目標

透過`race codition`取得server上的特定內容
造成`race codition`的方法是用送東西給server
||然後第三個我沒有寫出來 ~~儘管我透過demo偷聽別人講了甚麼來知道問題在哪~~ 造成我沒有A+||

## todo

1. `cha_1.c:show_fortune`這個function每次會被不同thread執行，他在讀檔案的時候會把檔案名稱存在`cha_1.c:20`這個全域變數裡面 -> race codition
    ```
    thread 1 37行 通過驗證                   39行 讀出來的是thread 2要求的檔案
    thread 2              29行 把全域變數蓋掉
    ```
    如果是上面這個執行順序就會讀到了
    所以就一直嘗試到獨到`flag{..`

2. `cha_1.c:56`有一個`get_hostbyname2` 直接用`man get_hostbyname2`看一下 就會發現這個function是un-thread-safe 恩 對就這樣
    :::warning
    不是回傳`cha_1.c:56`的`ent`這個變數有鬼 是上面的function本身記憶體的問題 
    :::
    還有 透過這個方法 要讓他跑大概兩三分鐘才回拿到`flag`
    助教有說如果送的東西正確 可以直接拿到 ||但我沒有那個能力思考||

3. `cha_3.c:136`和`cha_3.c:161` 這裡的fd被重複關閉了 好像是這樣
    所以大概是`"password.txt"`在某些情況被打開之後 裡面的帳號密碼是空的 所以只要送空的帳號密碼過去就回通過測試 直接過關 ~~可是我弄不出來~~
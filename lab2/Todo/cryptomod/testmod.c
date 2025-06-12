#include <linux/mutex.h>

static DEFINE_MUTEX(read_byte_mutex);       // 用於保護 read_byte
static DEFINE_MUTEX(write_byte_mutex);      // 用於保護 write_byte
static DEFINE_MUTEX(byte_freq_table_mutex); // 用於保護 byte_freq_table

// 假設這是你的全域變數
static int read_byte = 0;
static int write_byte = 0;
static int byte_freq_table[256] = {0};  // 假設是頻率表

// 使用 mutex_lock 和 mutex_unlock 的範例

void update_byte_data(void)
{
    // 加鎖 read_byte
    mutex_lock(&read_byte_mutex);
    read_byte = 42;  // 假設做某些操作
    mutex_unlock(&read_byte_mutex);

    // 加鎖 write_byte
    mutex_lock(&write_byte_mutex);
    write_byte = 100;  // 假設做某些操作
    mutex_unlock(&write_byte_mutex);

    // 加鎖 byte_freq_table
    mutex_lock(&byte_freq_table_mutex);
    byte_freq_table[read_byte]++;  // 假設根據 read_byte 更新頻率表
    mutex_unlock(&byte_freq_table_mutex);
}

// 另一個示範函式，讀取這些變數
void read_byte_data(void)
{
    // 讀取 read_byte 時加鎖
    mutex_lock(&read_byte_mutex);
    int byte_val = read_byte;
    mutex_unlock(&read_byte_mutex);

    // 讀取 write_byte 時加鎖
    mutex_lock(&write_byte_mutex);
    int write_val = write_byte;
    mutex_unlock(&write_byte_mutex);

    // 讀取 byte_freq_table 時加鎖
    mutex_lock(&byte_freq_table_mutex);
    int freq = byte_freq_table[byte_val];
    mutex_unlock(&byte_freq_table_mutex);
}

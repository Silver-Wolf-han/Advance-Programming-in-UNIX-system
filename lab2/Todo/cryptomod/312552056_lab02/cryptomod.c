/*
 * Lab problem set for UNIX programming course - LAB2
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>

// From sample_code.c
#include <linux/printk.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include "cryptomod.h"

#define MAX_BUFFER_SIZE 16384
#define BYTE_TABLE_SIZE 256

DEFINE_MUTEX(cryptodev_mutex);
DEFINE_MUTEX(byte_read_mutex);
DEFINE_MUTEX(byte_write_mutex);
DEFINE_MUTEX(byte_frequency_table_mutex);
// File descriptor: hint 7

struct cryptomod_data {
    pid_t pid;
    char* kernel_buffer;
    size_t cur_kernel_buffer_pos;
    struct CryptoSetup crypto_config;
    int device_setup;
    int finalize;
};

// From hellomod.c
static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static size_t byte_read = 0;
static size_t byte_write = 0;
static int byte_frequency_table[BYTE_TABLE_SIZE] = {0};

// modify from hellomod.c: free memory and reset dev state
static int cryptomod_dev_open(struct inode *i, struct file *f) {
    struct cryptomod_data *data;
    data = kmalloc(sizeof(struct cryptomod_data), GFP_KERNEL);
    if (!data) {
        return -ENOMEM;
    }
    f->private_data = data;
    data->device_setup = 0;
    data->finalize = 0;
    data->pid = current->pid;
    return 0;
}

// modify from hello.c
static int cryptomod_dev_close(struct inode *i, struct file *f) {
    struct cryptomod_data *data = f->private_data;
    if (data) {
        kfree(data);
    }
    return 0;
}

// from sample_code.c
static int test_skcipher(struct cryptomod_data *private_data, const size_t datasize)
{
    u8* key = private_data->crypto_config.key;
    size_t key_len = private_data->crypto_config.key_len;
    u8* data = private_data->kernel_buffer;

    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;
    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Error allocating ecb(aes) handle: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, key_len);
    if (err) {
        pr_err("Error setting key: %d\n", err);
        goto out;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        err = -ENOMEM;
        goto out;
    }

    sg_init_one(&sg, data, datasize); // You need to make sure that data size is mutiple of block size
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                       CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, datasize, NULL);
    if (private_data->crypto_config.c_mode == ENC) {
        err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    } else if (private_data->crypto_config.c_mode == DEC) {
        err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    }

    if (err) {
        pr_err("Error encrypting data: %d\n", err);
        goto out;
    }

    pr_debug("Encryption was successful\n");
out:
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    kfree(data);
    return err;
}

// write: write to kernel buffer
static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    mutex_lock(&cryptodev_mutex);
    struct cryptomod_data *data = f->private_data;
    printk("Start of write pid:%u\n", current->pid);
    if (!data->device_setup || data->finalize) {
        mutex_unlock(&cryptodev_mutex);
        return -EINVAL;
    }
    
    size_t process_bytes = min(len,  MAX_BUFFER_SIZE - data->cur_kernel_buffer_pos);
    if (process_bytes == 0) {
        mutex_unlock(&cryptodev_mutex);
        return -EAGAIN;
    }

    if (copy_from_user(data->kernel_buffer + data->cur_kernel_buffer_pos, buf, process_bytes)) {
        mutex_unlock(&cryptodev_mutex);
        return -EBUSY;
    }
    
    data->cur_kernel_buffer_pos += process_bytes;
    mutex_lock(&byte_write_mutex);
    byte_write += process_bytes;
    printk("End of write pid:%u\n", current->pid);
    mutex_unlock(&byte_write_mutex);
    mutex_unlock(&cryptodev_mutex);
    return process_bytes;
}

// read and process (dec or enc):
static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    mutex_lock(&cryptodev_mutex);
    printk("Start of read pid:%u\n", current->pid);
    struct cryptomod_data *data = f->private_data;
    if (!data->device_setup) {
        mutex_unlock(&cryptodev_mutex);
        return -EINVAL;
    }

    // keey at least a block in dev for padding
    size_t process_bytes = min(len - len % CM_BLOCK_SIZE, data->cur_kernel_buffer_pos - data->cur_kernel_buffer_pos % CM_BLOCK_SIZE);
    if (data->crypto_config.io_mode == ADV && data->crypto_config.c_mode == DEC && !data->finalize && data->cur_kernel_buffer_pos - process_bytes < CM_BLOCK_SIZE) {
        process_bytes -= CM_BLOCK_SIZE;
    }

    if (process_bytes == 0 && !data->finalize) {
        mutex_unlock(&cryptodev_mutex);
        return -EAGAIN;
    }
    
    // since padding remove is after dec process, so process dec in ioctl finalize mode
    if (data->crypto_config.c_mode == DEC && data->finalize) {
        process_bytes = min(len, data->cur_kernel_buffer_pos);
    } else {
        test_skcipher(data, process_bytes);
    }
    mutex_lock(&byte_frequency_table_mutex);
    if (data->crypto_config.c_mode == ENC) {
        for (size_t i = 0; i < process_bytes; ++i) {
            ++byte_frequency_table[(unsigned char)data->kernel_buffer[i]];
        }
    }
    mutex_unlock(&byte_frequency_table_mutex);
    if (copy_to_user(buf, data->kernel_buffer, process_bytes)) {
        mutex_unlock(&cryptodev_mutex);
        return -EBUSY;
    }

    data->cur_kernel_buffer_pos -= process_bytes;
    memmove(data->kernel_buffer, data->kernel_buffer + process_bytes, data->cur_kernel_buffer_pos);
    mutex_lock(&byte_read_mutex);
    byte_read += process_bytes;
    printk("End of read pid:%u\n", current->pid);
    mutex_unlock(&byte_read_mutex);
    mutex_unlock(&cryptodev_mutex);
    return process_bytes;
}

// ioctl
static long cryptomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
    mutex_lock(&cryptodev_mutex);
    struct cryptomod_data *data = fp->private_data;
    switch (cmd) {
    case CM_IOC_SETUP:
        printk("In ioctl setup pid:%u\n", current->pid);
        data->device_setup = 1;
        data->finalize = 0;
        data->cur_kernel_buffer_pos = 0;
        data->kernel_buffer = kmalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
        
        // error handling
        if ((struct CryptoSetup *)arg == NULL) {
            mutex_unlock(&cryptodev_mutex);
            return -EINVAL;
        }

        if (!data->kernel_buffer || copy_from_user(&(data->crypto_config), (struct CryptoSetup *)arg, sizeof(struct CryptoSetup))) {
            mutex_unlock(&cryptodev_mutex);
            return -EBUSY;
        }

        if (data->crypto_config.key_len != 16 && data->crypto_config.key_len != 24 && data->crypto_config.key_len != 32) {
            mutex_unlock(&cryptodev_mutex);
            return -EINVAL;
        }
        
        if (data->crypto_config.io_mode != BASIC && data->crypto_config.io_mode != ADV) {
            mutex_unlock(&cryptodev_mutex);
            return -EINVAL;
        }

        if (data->crypto_config.c_mode != ENC && data->crypto_config.c_mode != DEC) {
            mutex_unlock(&cryptodev_mutex);
            return -EINVAL;
        }
        
        memset(data->kernel_buffer, 0, MAX_BUFFER_SIZE);
        mutex_unlock(&cryptodev_mutex);
        return 0;
    case CM_IOC_FINALIZE:
        printk("In ioctl final pid:%u\n", current->pid);
        if (!data->device_setup) {
            mutex_unlock(&cryptodev_mutex);
            return -EINVAL;
        }
        data->finalize = 1;
        // padding
        switch (data->crypto_config.c_mode) {
        case ENC:
            if (data->cur_kernel_buffer_pos % CM_BLOCK_SIZE != 0) {
                char padding_value = CM_BLOCK_SIZE - data->cur_kernel_buffer_pos % CM_BLOCK_SIZE;
                while (data->cur_kernel_buffer_pos % CM_BLOCK_SIZE != 0) {
                    data->kernel_buffer[data->cur_kernel_buffer_pos++] = padding_value;
                }
            } else {
                for (size_t i = 0; i < CM_BLOCK_SIZE; ++i) {
                    data->kernel_buffer[data->cur_kernel_buffer_pos++] = CM_BLOCK_SIZE;
                }
            }
            mutex_unlock(&cryptodev_mutex);
            return 0;
        case DEC:
            if (data->cur_kernel_buffer_pos % CM_BLOCK_SIZE) {
                mutex_unlock(&cryptodev_mutex);
                return -EINVAL;
            }
            test_skcipher(data, data->cur_kernel_buffer_pos);
            unsigned char padding_value = data->kernel_buffer[data->cur_kernel_buffer_pos-1];
            int is_padding = 1;
            for (size_t i = 0; i < (size_t)padding_value && is_padding; ++i) {
                is_padding &= data->kernel_buffer[data->cur_kernel_buffer_pos-1-i] == padding_value;
            }
            if (!is_padding){
                mutex_unlock(&cryptodev_mutex);
                return -EINVAL;
            }
                
            while (data->kernel_buffer[data->cur_kernel_buffer_pos-1] == padding_value) {
                data->kernel_buffer[data->cur_kernel_buffer_pos--] = 0;
            }
            mutex_unlock(&cryptodev_mutex);
            return 0;
        default:
            mutex_unlock(&cryptodev_mutex);
            return 0;
        }
    case CM_IOC_CLEANUP:
        printk("In ioctl clean pid:%u\n", current->pid);
        if (!data->device_setup) {
            mutex_unlock(&cryptodev_mutex);
            return -EINVAL;
        }
        data->cur_kernel_buffer_pos = 0;
        memset(data->kernel_buffer, 0, MAX_BUFFER_SIZE);
        data->finalize = 0;
        mutex_unlock(&cryptodev_mutex);
        return 0;
    case CM_IOC_CNT_RST:
        printk("In ioctl rst pid:%u\n", current->pid);
        mutex_lock(&byte_read_mutex);
        mutex_lock(&byte_write_mutex);
        mutex_lock(&byte_frequency_table_mutex);
        byte_read = 0;
        byte_write = 0;
        memset(byte_frequency_table, 0, sizeof(byte_frequency_table));
        mutex_unlock(&byte_read_mutex);
        mutex_unlock(&byte_write_mutex);
        mutex_unlock(&byte_frequency_table_mutex);
        mutex_unlock(&cryptodev_mutex);
        return 0;
    default:
        mutex_unlock(&cryptodev_mutex);
        return -EINVAL;
    }
}

static const struct file_operations cryptomod_dev_fops = {
    .owner = THIS_MODULE,
    .open = cryptomod_dev_open,
    .read = cryptomod_dev_read,
    .write = cryptomod_dev_write,
    .unlocked_ioctl = cryptomod_dev_ioctl,
    .release = cryptomod_dev_close
};

// proc read: print the counter
static int cryptomod_proc_read(struct seq_file *m, void *v) {
    mutex_lock(&byte_read_mutex);
    mutex_lock(&byte_write_mutex);
    mutex_lock(&byte_frequency_table_mutex);
    seq_printf(m, "%zu %zu\n", byte_read, byte_write);
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            seq_printf(m, "%d ", byte_frequency_table[i * 16 + j]);
        }
        seq_printf(m, "\n");
    }
    mutex_unlock(&byte_read_mutex);
    mutex_unlock(&byte_write_mutex);
    mutex_unlock(&byte_frequency_table_mutex);
    return 0;
}


// From hellomod.c
static int cryptomod_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
    .proc_open = cryptomod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
 
static char *cryptomod_devnode(const struct device *dev, umode_t *mode) {
    if(mode == NULL) return NULL;
    *mode = 0666;
    return NULL;
}
 
static int __init cryptomod_init(void)
{
    // create char dev
    if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
        return -1;

    devnum = register_chrdev(0, "cryptodev", &cryptomod_dev_fops);
    if (devnum < 0) {
        return devnum;
    }
    
    if((clazz = class_create("upclass")) == NULL)
        goto release_region;
    clazz->devnode = cryptomod_devnode;
    if(device_create(clazz, NULL, MKDEV(devnum, 0), NULL, "cryptodev") == NULL)
        goto release_class;
    cdev_init(&c_dev, &cryptomod_dev_fops);
    if(cdev_add(&c_dev, devnum, 1) == -1)
        goto release_device;

    // create proc
    proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);

    printk(KERN_INFO "cryptomod: initialized.\n");
    return 0;    // Non-zero return means that the module couldn't be loaded.
 
release_device:
    device_destroy(clazz, devnum);
release_class:
    class_destroy(clazz);
release_region:
    unregister_chrdev_region(devnum, 1);
    return -1;
}

static void __exit cryptomod_cleanup(void)
{
    remove_proc_entry("cryptomod", NULL);

    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    printk(KERN_INFO "cryptomod: cleaned up.\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zjinghan");
MODULE_DESCRIPTION("The 2025 unix programming course - LAB2.");

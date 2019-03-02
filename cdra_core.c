#include <linux/version.h>   // needed to switch between vfs_ / kernel_read
#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/moduleparam.h> // needed for in/out parameters
#include <linux/kthread.h>     // needed for worker thread(s)
#include <linux/delay.h>       // needed for usleep...
#include <linux/syscalls.h>    // needed for symbol lookups (types)
#include <linux/kallsyms.h>    // needed for symbol lookups
#include <linux/socket.h>      // needed for socket/bind/recvfrom/sendto
#include <linux/net.h>         // needed for socket/bind/recvfrom/sendto
#include <linux/in.h>          // needed for socket/bind/recvfrom/sendto

/*
 * inet_addr() not available from kernel syms - here's a cheapy one
 */
static char inet_addr_bufarr[4];
unsigned int my_inet_addr(char *str) 
{ 
  int a,b,c,d; 
  sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d); 
  inet_addr_bufarr[0] = a; inet_addr_bufarr[1] = b;
  inet_addr_bufarr[2] = c; inet_addr_bufarr[3] = d; 
  return *(unsigned int*)inet_addr_bufarr; 
} 


#if 0 || defined (CDRA_NOT_NEEDED_AS_FAR_AS_I_CAN_TELL)
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#endif

#include "cdra.h"

//long sys_socket(int, int, int);
static int (*sys_socketp)
  (int domain, int type, int protocol);

//long sys_close(unsigned int fd);
static int (*sys_closep)
  (unsigned int fd);

//long sys_getsockname(int, struct sockaddr __user *, int __user *);
static int (*sys_getsocknamep)
  (int fd, struct sockaddr /* __user */ *addr, int __user *addr_len);

//long sys_bind(int, struct sockaddr __user *, int);
static int (*sys_bindp)
  (int fd, struct sockaddr /* __user */ *addr, int addr_len);

//long sys_recvfrom(int, void __user *, size_t, unsigned,
//         struct sockaddr __user *, int __user *);
static int (*sys_recvfromp)
   (int fd, void __user *ubuf, size_t size,
    unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);

//long sys_sendto(int, void __user *, size_t, unsigned,
//      struct sockaddr __user *, int);
static int (*sys_sendtop)
  (int fd, void __user *ubuf, size_t len,
   unsigned int flags, struct sockaddr __user *addr, int addr_len);

static struct file * driver_file_open(const char *path, int flags, int mode);
static void driver_file_close(struct file *filp);
static int driver_file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size);

#define CDRA_ADC_CHANNELS_COUNT 6

/*
 * parameters
 */
static char *serverName = "127.0.0.1" ;
//module_param(serverName, charp, 0644);
static int param_set_optitrack_serverName(const char *val,
                               const struct kernel_param *kp)
{

       int ret = param_set_charp(val, kp);
       printk(KERN_INFO "%s optitrack_serverName = %s\n",
         __func__, serverName);

       return ret;
}
static struct kernel_param_ops params_cdra_optitrack_serverName = {
       .set = param_set_optitrack_serverName,
       .get = param_get_charp,
};
module_param_cb(serverName, &params_cdra_optitrack_serverName, &serverName, 0644);
MODULE_PARM_DESC(serverName, "Optitrack server name/ipaddr");

static int serverPort = 1511 ;
module_param(serverPort, int, 0644);
MODULE_PARM_DESC(serverPort, "Optitrack server port");

static bool serverConnect = 0 ;  /* default to off */
module_param(serverConnect, bool, 0644);
MODULE_PARM_DESC(serverConnect, "Optitrack server connect on=1; 0=off*");

static bool rcinDebug = 0 ;  /* default to off */
module_param(rcinDebug, bool, 0644);
MODULE_PARM_DESC(rcinDebug, "Generate a random number for rcin on=1; 0=off*");

static bool adcDebug = 0 ;  /* default to off */
module_param(adcDebug, bool, 0644);
MODULE_PARM_DESC(adcDebug, "Generate a random number for adc on=1; 0=off*");

struct cdra_state cdra_state;
struct task_struct *task;

/*
 * worker kthread for udp/optitrack inbound messages
 */
unsigned char mystaticbuf[512];

int udpworker(void *data)
{
  int udp_pkts_in = 0;
  int udp_pkts_out = 0;
  int sd;
  int ret;
  int closeret=999;
  int len;
  int once = 1;
  struct sockaddr_in udpworkeraddr;
  struct sockaddr_in optitrackaddr;
  struct sockaddr recvaddr;
  int addr_len = (int) sizeof (recvaddr);
#if 1
  mm_segment_t    oldfs;
#endif

  /*
   * get socket for udp I/O
   */
#if 1
  oldfs   = get_fs();
  set_fs(get_ds());
#endif
  sd = sys_socketp (AF_INET, SOCK_DGRAM, 0);
#if 1
  set_fs(oldfs);
#endif
  if (sd<0) {
    printk(KERN_INFO "Failed creating socket\n");
    ret = -1;
    goto errout_setup;
  }

  /*
   * bind to socket for sendto/recvfrom
   */
  udpworkeraddr.sin_family = AF_INET;
  udpworkeraddr.sin_addr.s_addr = htonl(INADDR_ANY);
  udpworkeraddr.sin_port = htons(0);

  optitrackaddr.sin_family = AF_INET;
  optitrackaddr.sin_addr.s_addr = my_inet_addr (serverName);
  optitrackaddr.sin_port = htons(serverPort);

#if 1
  oldfs   = get_fs();
  set_fs(get_ds());
#endif
  ret = sys_bindp(sd,
    (struct sockaddr *) &udpworkeraddr,
    sizeof(udpworkeraddr));
#if 1
  set_fs(oldfs);
#endif
  if(ret<0) {
    printk(KERN_INFO "Failed binding socket\n");
    ret = -1;
    goto errout_setup;
  }

  /*
   * TODO: report my locally assigned port number for recvfrom
   *       used here for debug and test - not needed for production
   */
  addr_len = sizeof(udpworkeraddr);
#if 1
  oldfs   = get_fs();
  set_fs(get_ds());
#endif
  ret = sys_getsocknamep(sd,
    (struct sockaddr *)&udpworkeraddr, &addr_len);
#if 1
  set_fs(oldfs);
#endif

  printk (KERN_INFO "cdra_uworker on (sd=%d, port=%d)\n",
    sd, ntohs(udpworkeraddr.sin_port));

  /*
   * stay here and loop until told to stop
   */
  while (!kthread_should_stop())
  {
    /*
     * only work with optitrack packets with serverConnect = true
     * TODO: for test, usleep is 1.2 - 1.5ms, optitrack is at 120Hz
     *       will need to PEEK/fcntl/poll the fd in the event
     *       optitrack is not running so kthread can honor should_stop()
     */
    if (serverConnect) {
#if 1
      oldfs   = get_fs();
      set_fs(get_ds());
#endif
      len = sys_recvfromp (sd,
                           &mystaticbuf[0], sizeof(mystaticbuf),
                           MSG_DONTWAIT, &recvaddr, &addr_len);
#if 1
      set_fs(oldfs);
#endif
      if (len >= 0) {
        udp_pkts_in++;
        printk (KERN_INFO "got message of len=%d (%d)\n", len, udp_pkts_in);
      } else {
        if (once == 1) {
          printk (KERN_INFO "error of len=%d (%d)\n", len, udp_pkts_in);
          once = 0;
        }
      }
      ; // do udp io
    }
    usleep_range (1000, 1500);
  }

  // normal exit
  ret = 0;

errout_setup:
  if (sd >= 0) {
#if 1
    oldfs   = get_fs();
    set_fs(get_ds());
#endif
    // otherwise kthreadd (pid = 2) will keep open, see 'lsof -np 2'
    closeret = sys_closep (sd); 
#if 1
    set_fs(oldfs);
#endif
  }

  printk (KERN_INFO
    "kthread_should_stop: ret=%d sd=%d pkts=(%d/%d) close=%d\n",
     ret, sd, udp_pkts_in, udp_pkts_out, closeret);

  do_exit(ret);
  return (ret);
}

/*
 * read (show) group files in sysfs (exposed to user space)
 */
static ssize_t rcin_channel_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
  ssize_t channel = -1;
  char fname[80];
  char lbuf[80];

  if (!strcmp(attr->attr.name, "ch0")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch1")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch2")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch3")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch4")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch5")) {
      channel = 0;
  }

  memset( lbuf, 0, sizeof(lbuf) );

  if (channel < 0) {
      return -EBUSY;
  } else if (channel == 0) {
      if (rcinDebug) {
        int i;
        get_random_bytes(&i, sizeof(int));
        i = (i % 1024) + 1024;
        sprintf (lbuf, "%d", i);
      }
      else {
        struct file *filp = NULL;
        int ret;
        sprintf (fname, "/sys/kernel/rcio/rcin/%s", attr->attr.name);
        if ((filp = driver_file_open (fname, O_RDONLY, 0)) != NULL)
        {
          //printk(KERN_INFO "fp=%llx, lbuf=%llx, s=%d, f='%s'\n", (long long int)filp, (long long int)&lbuf[0], sizeof(lbuf), fname);
          ret = driver_file_read (filp, 0, &lbuf[0], sizeof(lbuf));
          if ((ret > -1) && (ret < sizeof(lbuf))) lbuf[ret] = 0;
          driver_file_close (filp);
        }
      }
  }
  return sprintf(buf, "%s", lbuf);
}

static ssize_t adc_channel_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
  ssize_t channel = -1;
  char fname[80];
  char lbuf[80];

  if (!strcmp(attr->attr.name, "ch0")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch1")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch2")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch3")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch4")) {
      channel = 0;
  } else if (!strcmp(attr->attr.name, "ch5")) {
      channel = 0;
  }

  memset( lbuf, 0, sizeof(lbuf) );

  if (channel < 0) {
      return -EBUSY;
  } else if (channel == 0) {
      if (adcDebug) {
        int i;
        get_random_bytes(&i, sizeof(int));
        i = (i % 1024) + 1024;
        sprintf (lbuf, "%d", i);
      }
      else {
        struct file *filp = NULL;
        int ret;
        sprintf (fname, "/sys/kernel/rcio/adc/%s", attr->attr.name);
        if ((filp = driver_file_open (fname, O_RDONLY, 0)) != NULL)
        {
          //printk(KERN_INFO "fp=%llx, lbuf=%llx, s=%d, f='%s'\n", (long long int)filp, (long long int)&lbuf[0], sizeof(lbuf), fname);
          ret = driver_file_read (filp, 0, &lbuf[0], sizeof(lbuf));
          if ((ret > -1) && (ret < sizeof(lbuf))) lbuf[ret] = 0;
          driver_file_close (filp);
        }
      }
  }

  return sprintf(buf, "%s", lbuf);
}

static struct kobj_attribute rcin_ch0_attribute = __ATTR(ch0, S_IRUGO, rcin_channel_show, NULL);
static struct kobj_attribute rcin_ch1_attribute = __ATTR(ch1, S_IRUGO, rcin_channel_show, NULL);
static struct kobj_attribute rcin_ch2_attribute = __ATTR(ch2, S_IRUGO, rcin_channel_show, NULL);
static struct kobj_attribute rcin_ch3_attribute = __ATTR(ch3, S_IRUGO, rcin_channel_show, NULL);
static struct kobj_attribute rcin_ch4_attribute = __ATTR(ch4, S_IRUGO, rcin_channel_show, NULL);
static struct kobj_attribute rcin_ch5_attribute = __ATTR(ch5, S_IRUGO, rcin_channel_show, NULL);

static struct attribute *rcin_attrs[] = {
  &rcin_ch0_attribute.attr,
  &rcin_ch1_attribute.attr,
  &rcin_ch2_attribute.attr,
  &rcin_ch3_attribute.attr,
  &rcin_ch4_attribute.attr,
  &rcin_ch5_attribute.attr,
  NULL,
};

static struct attribute_group rcin_attr_group = {
  .name = "rcin",
  .attrs = rcin_attrs,
};

static struct kobj_attribute adc_ch0_attribute = __ATTR(ch0, S_IRUGO, adc_channel_show, NULL);
static struct kobj_attribute adc_ch1_attribute = __ATTR(ch1, S_IRUGO, adc_channel_show, NULL);
static struct kobj_attribute adc_ch2_attribute = __ATTR(ch2, S_IRUGO, adc_channel_show, NULL);
static struct kobj_attribute adc_ch3_attribute = __ATTR(ch3, S_IRUGO, adc_channel_show, NULL);
static struct kobj_attribute adc_ch4_attribute = __ATTR(ch4, S_IRUGO, adc_channel_show, NULL);
static struct kobj_attribute adc_ch5_attribute = __ATTR(ch5, S_IRUGO, adc_channel_show, NULL);

static struct attribute *adc_attrs[] = {
  &adc_ch0_attribute.attr,
  &adc_ch1_attribute.attr,
  &adc_ch2_attribute.attr,
  &adc_ch3_attribute.attr,
  &adc_ch4_attribute.attr,
  &adc_ch5_attribute.attr,
  NULL,
};

static struct attribute_group adc_attr_group = {
  .name = "adc",
  .attrs = adc_attrs,
};

/*
 * file I/O routines (read only)
 */
static
struct file *
driver_file_open(const char *path, int flags, int mode)
{
  struct file *filp = NULL;
  mm_segment_t    oldfs;
  oldfs   = get_fs();
  set_fs(get_ds());
  filp = filp_open(path, flags, mode /* only used with O_CREAT) S_IRWXU|S_IRWXG|S_IRWXO */);
  if (IS_ERR(filp))
  {
    filp=NULL;
  }
  set_fs(oldfs);
  return (filp);
}

static void
driver_file_close(struct file *filp)
{
  if (filp != NULL)
    filp_close(filp, NULL);
}

#if 0 || defined (CDRA_ENABLE_FILE_WRITE)
int
driver_file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
  int     ret;
  loff_t  pos = offset;
#if 1
  mm_segment_t    oldfs;
  oldfs   = get_fs();
  set_fs(get_ds());
#endif

#if 1
  if (pos > 0) vfs_setpos(file, pos, pos + PAGE_SIZE);
#else
  //Workaround for vfs_setpos, not implemented on my version of linux.
  spin_lock(&file->f_lock);
  file->f_pos = pos;
  //file->f_version = 0;
  spin_unlock(&file->f_lock);
#endif
  //printk(KERN_INFO "set position to  %llx\n", pos);

  ret = vfs_write(file, data, size, &pos);
  //vfs_fsync(file, 0);
#if 1
  set_fs(oldfs);
#endif
  return (ret);
}
#endif // defined (CDRA_ENABLE_FILE_WRITE)

static int
driver_file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
  int     ret;
  loff_t  pos = offset;
#if 1
  mm_segment_t    oldfs;
  oldfs   = get_fs();
  set_fs(get_ds());
#endif

#if 1
  if (pos > 0) vfs_setpos(file, pos, pos + PAGE_SIZE);
#else
  //Workaround for vfs_setpos, if not implemented on my version of linux.
  spin_lock(&file->f_lock);
  file->f_pos = pos;
  //file->f_version = 0;
  spin_unlock(&file->f_lock);
#endif
  //printk(KERN_INFO "set position to read %llx\n", pos);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,14)
  ret = vfs_read(file, data, size, &pos);
#else
  ret = kernel_read(file, data, size, &pos);
#endif
  //vfs_fsync(file, 0);
#if 1
  set_fs(oldfs);
#endif
  return (ret);
}

/*
 * module init routine (main)
 */
static int /* __init */ cdra_init(void)
{
    int ret;

#if 0 || defined(CDRA_TESTFILE_IO)
    struct file *filp = NULL;
    unsigned char buf[300];
    const char *fname = "/sys/kernel/rcio/adc/ch0"; // "/sys/kernel/debug/sched_features"; //"/sys/kernel/security/ima/ascii_runtime_measurements";

    filp = driver_file_open (fname, O_RDONLY, 0);
    if (filp <= (struct file *)NULL)
    {
      // do nothing now, file may not exist here
    }
    else
    {
      memset( buf, 0, sizeof(buf) );
      ret = driver_file_read (filp, 0, &buf[0], sizeof(buf));
      if ((ret > -1) && (ret < sizeof(buf))) buf[ret] = 0;
      driver_file_close (filp);
      printk(KERN_INFO "read %d bytes having '%s'\n", ret, &buf[0]);
    }
#endif

    /*
     * setup /sys/kernel/cdra/[rcin|adc|stats] (all read-only)
     */
    cdra_state.object = kobject_create_and_add("cdra", kernel_kobj);

    if (cdra_state.object == NULL) {
        return -EINVAL;
    }

    ret = sysfs_create_group(cdra_state.object, &rcin_attr_group);

    if (ret < 0) {
        printk(KERN_INFO "sysfs for rcin failed\n");
        goto errout_allocated;
    }

    ret = sysfs_create_group(cdra_state.object, &adc_attr_group);

    if (ret < 0) {
        printk(KERN_INFO "sysfs for adc failed\n");
        goto errout_allocated;
    }

    /*
     * udp setup/stuff
     * - find needed symbols in the kernel
     */
    sys_socketp = (int(*)(int domain, int type, int protocol))
      kallsyms_lookup_name("sys_socket");
    if ( ( (unsigned long)sys_socketp) == 0) {
      printk(KERN_INFO "Failed to obtained sys_socket pointer\n");
      goto errout_lookup;
    }

    sys_closep = (int(*)(unsigned int fd))
      kallsyms_lookup_name("sys_close");
    if ( ( (unsigned long)sys_closep) == 0) {
      printk(KERN_INFO "Failed to obtained sys_close pointer\n");
      goto errout_lookup;
    }

    sys_getsocknamep = (int(*)(int fd, struct sockaddr /* __user */ *addr, int __user *addr_len))
      kallsyms_lookup_name("sys_getsockname");
    if ( ( (unsigned long)sys_getsocknamep) == 0) {
      printk(KERN_INFO "Failed to obtained sys_getsockname pointer\n");
      goto errout_lookup;
    }

    sys_bindp = (int(*)(int fd, struct sockaddr /*__user */ *addr, int addr_len))
      kallsyms_lookup_name("sys_bind");
    if ( ( (unsigned long)sys_bindp) == 0) {
      printk(KERN_INFO "Failed to obtained sys_bind pointer\n");
      goto errout_lookup;
    }

    sys_recvfromp = (int(*)(int fd, void __user *ubuf,
      size_t size, unsigned int flags, struct sockaddr __user *addr,
      int __user *addr_len))
        kallsyms_lookup_name("sys_recvfrom");

    if ( ( (unsigned long)sys_recvfromp) == 0) {
      printk(KERN_INFO "Failed to obtained sys_recvfrom pointer\n");
      goto errout_lookup;
    }

    sys_sendtop = (int (*)(int fd, void __user *ubuf,
      size_t size, unsigned int flags, struct sockaddr __user *addr,
      int addr_len))
        kallsyms_lookup_name("sys_sendto");

    if (((unsigned long)sys_sendtop) == 0){
      printk(KERN_INFO "Failed to obtained sys_sendto pointer\n");
      goto errout_lookup;
    }

    /*
     * start our kernel thread(s)
     */
    task = kthread_run(&udpworker, (void *)&cdra_state,"cdra_uworker");

    /*
     * announce to the world were are here
     */
    printk(KERN_INFO "Hello CDRA here! (s=%s:%d (%s))\n",
      serverName, serverPort, serverConnect==0?"off":"on");

    return 0;

errout_allocated:
errout_lookup:
    kobject_put(cdra_state.object); // shouldn't this be put(0)?
    return -EIO;
}

/*
 * module stop (exit) routine
 */
static void cdra_stop(void)
{
    int ret;

    ret = kthread_stop(task);

    printk(KERN_INFO "Stopping CDRA module! (s=%s:%d (%s), task=%d)\n",
      serverName, serverPort, serverConnect==0?"off":"on", ret);

    kobject_put(cdra_state.object); // shouldn't this be _put(0)?

    return;
}

//int cdra_probe(struct cdra_adapter *adapter)
int cdra_probe(void)
{
    if (cdra_init() < 0) {
        goto errout_init;
    }

    return 0;

errout_init:
    return -EBUSY;
}

//int cdra_remove(struct cdra_adapter *adapter)
int cdra_remove(void)
{
    int ret = 0;

    cdra_stop();

    return ret;
}

module_init(cdra_init); // necessary
module_exit(cdra_stop); // necessary

EXPORT_SYMBOL_GPL(cdra_probe);  // can be called from others
EXPORT_SYMBOL_GPL(cdra_remove); // can be called from others

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("shissam");
MODULE_DESCRIPTION("CDRA Runtime Monitor for Navio2 RCIO LKM");


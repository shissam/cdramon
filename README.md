# cdramon

## Copyright

## Prerequisites

assuming you have the linux kernel headers installed. for Ubuntu 16.04 I
seem to have gotten those for free given that I had virtualbox installed
which has a dkms module.  for raspberrypi with Navio2 hat, the emlib
distro already had the linux tools there.

### Kernel header (raspbian)

`sudo apt-get install raspberrypi-kernel-headers`

### Kernel header (debian/ubuntu)

instructions forthcoming!

## Compiling

basically:

   $ make

## Example/Debug

   $ sudo insmod cdra_core.ko
   $ dmesg | tail -2
     [1233682.450736] Hello CDRA here! (s=127.0.0.1:1511 (off))
     [1233682.450749] cdra_uworker on (sd=0, port=39192)
   $
   $ cd /sys/module/cdra_core/parameters
     -rw-r--r-- 1 root root 4096 Jan 18 17:36 adcDebug
     -rw-r--r-- 1 root root 4096 Jan 18 17:36 rcinDebug
     -rw-r--r-- 1 root root 4096 Jan 18 17:36 serverConnect
     -rw-r--r-- 1 root root 4096 Jan 18 17:36 serverName
     -rw-r--r-- 1 root root 4096 Jan 18 17:36 serverPort

   $ echo $(cat /sys/kernel/cdra/rcin/ch0)
   $ 
   $ echo "1" > rcinDebug
   $ echo $(cat /sys/kernel/cdra/rcin/ch0)
     1614
   $ echo $(cat /sys/kernel/cdra/rcin/ch0)
     895

   $ echo "0" > rcinDebug
   $ echo $(cat /sys/kernel/cdra/rcin/ch0)

### same behavior for adc

   $ sudo lsmod |grep cdra
     cdra_core              16384  0

   $ sudo rmmod cdra_core
   $ dmesg|tail -2
     [1233929.033524] kthread_should_stop: ret=0 sd=0 pkts=(0/0) close=0
     [1233929.033533] Stopping CDRA module! (s=127.0.0.1:1511 (off), task=0)



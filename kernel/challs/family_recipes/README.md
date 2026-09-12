## Run the challenge locally
The challenge comes with 2 wrapper scripts (`run.py` and `run.sh`) used to make qemu load the exploit executable inside the rootfs. The Python script asks for a URL to download your exploit executable; the .sh file loads the executable from the local file system.  

Run 
```
python3 run.py 
```
and then provide a URL, or run
```
./run.sh /path/to/local/executable/file
```

# Exploit skeleton
```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define CHALLENGE_DRIVER "/dev/chall"
// Commands
#define CMD_ALLOC 1337
#define CMD_DELETE 1338
#define CMD_READ 1339
#define CMD_INFO 1340
#define CMD_TOGGLE 1341

static int fd;

int main(int argc, char **argv) {

    // Open challenge driver
    printf("[*] Opening challenge driver...\n");
    fd = open(CHALLENGE_DRIVER, O_RDWR | O_NONBLOCK);

    // ------- Exploit here -------

    close(fd);
    return 0;

}
```
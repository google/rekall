#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>


int main(int argc, char **argv)
{
	struct stat s;
	unsigned char *one;
	unsigned char *two;
	int fd1 = open(argv[1],O_RDONLY);
	int fd2 = open(argv[2],O_RDONLY);

	if(fd1 == -1 || fd2 == -1)
		return 1;

	if(fstat(fd1,&s) == -1)
		return 1;

	one = calloc(1,s.st_size);
	if(!one)
		return 1;
	
	if(read(fd1,one,s.st_size) != s.st_size)
		return 1;

	if(fstat(fd2,&s) == -1)
		return 1;
	
	two = calloc(1,s.st_size);
	if(!two)
		return 1;
	
	 if(read(fd2,two,s.st_size) != s.st_size)
		return 1;

	int size = s.st_size;
	int cur = 0;
    unsigned char x, y;	
    int last = -1;

	while(cur < size)
	{
        x = *one;
        y = *two;

		if(x != y)
        {
            if(last != -1 && last != cur - 1)
                printf("\n----\n");
			printf("%d 0x%x | %x | %x\n",cur, cur, x, y);
            last = cur;
        }

        one++; two++;
		cur++;
		

	}

	
	return 0;
}

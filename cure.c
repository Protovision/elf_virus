#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>

#define VIRUS_SIZE	13840
#define VIRUS_MAGIC	7177135
#define CURE_TMPFILE	".cure.tmp"
	
int main(int argc, const char **argv) {
	int fd, tfd, magic;
	struct stat st;

	fd = open(argv[1], O_RDWR);
	if (fd == -1) return 1;

	lseek(fd, sizeof(magic) * -1, SEEK_END);
	read(fd, &magic, sizeof(magic));
	if (magic != VIRUS_MAGIC) {
		close(fd);
		return 0;
	}
	
	fstat(fd, &st);
	tfd = creat(CURE_TMPFILE, st.st_mode);
	if (tfd == -1) return 1;
	
	lseek(fd, VIRUS_SIZE, SEEK_SET);
	sendfile(tfd, fd, NULL, st.st_size - VIRUS_SIZE - sizeof(magic));
	close(tfd);
	close(fd);

	rename(".cure.tmp", argv[1]);
	return 0;	
}	

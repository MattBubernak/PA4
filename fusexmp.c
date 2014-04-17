/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR
#define BB_DATA ((struct bb_state *) fuse_get_context()->private_data)
#define PATH_MAX 200

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
/* Linux is missing ENOATTR error, using ENODATA instead */
#define ENOATTR ENODATA
#endif


#include <sys/xattr.h>
#include <linux/xattr.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include "aes-crypt.h"


#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif


struct bb_state {
    FILE *logfile;
    char *rootdir;
} ;


static struct bb_state bb_data = {NULL,NULL}; 

char* key_str = "nudlyf"; //key used for encryption 
char* flag = "user.pa4-encfs.encrypted";

void fixPath(char newPath[PATH_MAX],const char * path)
{
	newPath = strcpy(newPath,bb_data.rootdir); 
	newPath = strcat(newPath,path); 
}


static int xmp_getattr(const char *path, struct stat *stbuf)
{
	
	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 
	
	int res;

	res = lstat(newPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = access(newPath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;


	res = readlink(newPath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path);  

	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(newPath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(newPath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = mkdir(newPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = unlink(newPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = rmdir(newPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{


	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{


	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{


	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = chmod(newPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = lchown(newPath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = truncate(newPath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(newPath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = open(newPath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int fd;
	int res;
	int action = 0; // this indicates decrypt 

	(void) fi;

	//check encryption
        char* tmpstr = NULL;
        char* tmpval = NULL;
        ssize_t valsize = 0;

	/* Get attribute value size */
	valsize = getxattr(newPath, "user.pa4-encfs.encrypted", NULL, 0);
	if(valsize < 0){
	    if(errno == ENOATTR){
		fprintf(stdout, "No %s attribute set on %s\n", tmpstr, newPath);
		free(tmpstr);
		return EXIT_SUCCESS;
	    }
	    else{
		perror("getxattr error");
		fprintf(stderr, "path  = %s\n", newPath);
		fprintf(stderr, "name  = %s\n", tmpstr);
		fprintf(stderr, "value = %s\n", "NULL");
		fprintf(stderr, "size  = %zd\n", valsize);
		exit(EXIT_FAILURE);
	    }
	}
	/* Malloc Value Space */
	tmpval = malloc(sizeof(*tmpval)*(valsize+1));
	if(!tmpval){
	    perror("malloc of 'tmpval' error");
	    exit(EXIT_FAILURE);
	}
	/* Get attribute value */
	valsize = getxattr(newPath,  "user.pa4-encfs.encrypted", tmpval, valsize);
	if(valsize < 0){
	    if(errno == ENOATTR){
		fprintf(stdout, "No %s attribute set on %s\n", tmpstr, newPath);
		free(tmpval);
		return EXIT_SUCCESS;
	    }
	    else{
		perror("getxattr error");
		fprintf(stderr, "path  = %s\n", newPath);
		fprintf(stderr, "name  = %s\n", tmpstr);
		fprintf(stderr, "value = %s\n", tmpval);
		fprintf(stderr, "size  = %zd\n", valsize);
		free(tmpval);
		exit(EXIT_FAILURE);
	    }
	}
	
	/* Print Value */
	tmpval[valsize] = '\0';
	fprintf(stdout, "%s = %s\n", tmpstr, tmpval);


	if (tmpval == "true")
	{
		//TODO decrypt file
	}

	free(tmpval);



	//if encrypted, decrypt the file, if it's not encrypted don't decrypt 
	fd = open(newPath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int fd;
	int res;
	int action = 1; // this indicates encrypt 

	(void) fi;
	//encrypt the file, unless it's an un-encrypted file. check flag? 
	fd = open(newPath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res;

	res = statvfs(newPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    //create a new path  
    char newPath[PATH_MAX]; 
    fixPath(newPath,path); 

    (void) fi;

    int action = 1; // this indicates encrypt 
    FILE* file = NULL;
    
    //encrypt the file, since it's a new file 
    
 
    //strmode(mode,modeString); 

    /* Open Files */
    file = fopen(newPath,"w");
    if(!file){
	fprintf(stderr, "failed to open infile\n");
	return EXIT_FAILURE;
    }
    


    /* Perform do_crpt action (encrypt, decrypt, copy) */
    if(!do_crypt(file, file, action,key_str)){
	fprintf(stderr, "do_crypt failure\n");
	return -errno; 
    }


    /* Cleanup */
    if(fclose(file)){
		return -errno;
    }
    
   //TODO: flag as encrypted 


	if(setxattr(newPath, flag, "true", strlen("true"), 0)){
	    perror("setxattr error");

	    exit(EXIT_FAILURE);
	}






    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res = lsetxattr(newPath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res = lgetxattr(newPath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res = llistxattr(newPath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{

	//create a new path 
	char newPath[PATH_MAX]; 
	fixPath(newPath,path); 

	int res = lremovexattr(newPath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};




int main(int argc, char *argv[])
{
	umask(0);
	//phrase, mirror dir, mount point
	//path information
	printf("Mounting from: %s\n",argv[argc-2]);
	printf("Mounting to: %s\n",argv[argc-1]);
	printf("Mounting key: %s\n",argv[argc-3]);

	//grab the key 
	key_str = argv[argc-3]; 

	//change the root directory to the one we are supplying. 
	bb_data.rootdir = realpath(argv[argc-2], NULL); 
	printf("New Root Dir: %s\n",bb_data.rootdir); 
	//remove that path after we use it... 
	argv[argc-3] = argv[argc-1];
	argc--; 
	argc--; 
	return fuse_main(argc, argv, &xmp_oper, NULL);
}

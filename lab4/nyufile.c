
#include <string.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <math.h>
#define SHA_DIGEST_LENGTH 20
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)
#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)
struct stat size;
void printOptions(char* disk,char* filename){
    printf("Usage: %s %s <options>\n",filename,disk);
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");

}
void systemInfo(int numFAT,int byteSEC,int secCLUS,int resSEC){
    printf("Number of FATs = %d\n",numFAT);
    printf("Number of bytes per sector = %d\n",byteSEC);
    printf("Number of sectors per cluster = %d\n",secCLUS);
    printf("Number of reserved sectors = %d\n",resSEC);
}
int checkHASH(unsigned char* sha1,char* input,int sha1LEN){
    //-1 if not equal 1 if equal
    char* full=malloc(0);
    int count = 2;
    for(int i = 0; i < sha1LEN;i++){
        char conv[4];
        full=realloc(full,count);
        snprintf(conv,3,"%02x",sha1[i]);
        strcat(full,conv);
        count+=2;
    }
    if(strcmp(full,input)==0)return 1;
    else return -1;
    free(full);
}

int main(int argc, char* argv[]){
    
    struct BootEntry *entry;
    struct DirEntry *dir;
    unsigned char* mappedAD;
    int file;

    if(argc==2&&strstr(argv[1],"-")!=NULL){
        printOptions("disk",argv[0]);
        return 0;
    }
    if(argc>=2){
        file=open(argv[1],O_RDWR);
        fstat(file,&size);
        mappedAD = mmap(NULL,size.st_size,PROT_READ | PROT_WRITE,MAP_SHARED,file,0);
        if(file==-1){
            printOptions("disk",argv[0]);
            return 0;
        }
    }
    entry=(BootEntry *)(mappedAD);
    int x =(entry->BPB_RsvdSecCnt)*(entry->BPB_BytsPerSec) + (((entry->BPB_NumFATs) * (entry->BPB_FATSz32))*entry->BPB_BytsPerSec) + (entry->BPB_SecPerClus*entry->BPB_BytsPerSec*(entry->BPB_RootClus-2));

    //X is the starting point of the root directeory 
    int* FAT= (int *)(mappedAD+(entry->BPB_BytsPerSec*entry->BPB_RsvdSecCnt));

    if(argc==1){
        printOptions("disk",argv[0]);
        return 0;
    }
    else if(argc==2){
        printOptions(argv[1],argv[0]);
        return 0;
    }
    else if((strcmp(argv[2],"-i")!=0) && (strcmp(argv[2],"-l")!=0) && (strcmp(argv[2],"-r")!=0) && (strcmp(argv[2],"-R")!=0)){
        printOptions(argv[1],argv[0]);
        return 0;
    }
    else if(argc>3 &&((strcmp(argv[2],"-i")==0) || (strcmp(argv[2],"-l")==0))){
        printOptions(argv[1],argv[0]);
        return 0;
    }
    else if(strcmp(argv[2],"-r")==0 ){
        //check to make sure -r is formatted in valid way
        if(argc<4)printOptions(argv[1],argv[0]);
        if(argc>=5){
            if(strcmp(argv[4],"-s")!=0 || argc<6){
                printOptions(argv[1],argv[0]);
                return 0;
            }
        }
        if(argc>=5 && strcmp(argv[4],"-s")==0){
            //USE SHA-1
            
            int prevRootClus=entry->BPB_RootClus;
            int buff = x;
            int count=0;
            char* name=malloc(0);
            char* end=malloc(0);
            int found =-1;
            dir=(DirEntry *)(mappedAD+buff);
            
            while(dir->DIR_Name[0]!=0x00){
                
                //Format file name
                for(int i=0;i<=7;i++){
                    if(dir->DIR_Name[i]==' ')break;
                    name=realloc(name,i+1);
                    name[i]=dir->DIR_Name[i];
                    
                }
                for(int i = 0;i<3;i++){
                    if(dir->DIR_Name[i+8]==' ')break;
                    end=realloc(end,i+1);
                    end[i]=dir->DIR_Name[i+8];
                    
                }
                if(strlen(end)>0){
                    name=realloc(name,strlen(end)+1);
                    strcat(name,".");
                    strcat(name,end);
                }
                name[0]=argv[3][0];
                name[strcspn(name, "\r\n")] = 0;
                
                if(strcmp(argv[3],name)==0 && (dir->DIR_Name[0]==0xe5)){
                    unsigned char* fileCONT=(mappedAD+(entry->BPB_RsvdSecCnt)*(entry->BPB_BytsPerSec) + (((entry->BPB_NumFATs) * (entry->BPB_FATSz32))*entry->BPB_BytsPerSec) + (entry->BPB_SecPerClus*entry->BPB_BytsPerSec*(dir->DIR_FstClusLO-2)));
                    unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
                    SHA1(fileCONT, dir->DIR_FileSize, hash);
                    int cH = checkHASH(hash,argv[5],SHA_DIGEST_LENGTH);
                    if(cH==1){
                        found=1;
                        FAT = (int *)(mappedAD+(entry->BPB_BytsPerSec*entry->BPB_RsvdSecCnt));
                        printf("%s: successfully recovered with SHA-1\n",argv[3]);
                        dir->DIR_Name[0]=argv[3][0];
                        //Change *ALL* FATs
                        for(int m=0;m<entry->BPB_NumFATs;m++){
                            //ASSUMED TO BE CONTIGUOSLY ALLOCATED! :)
                            if(dir->DIR_FileSize<512)FAT[dir->DIR_FstClusLO+2]=0x0ffffff8; //Smaller than 1 cluster!
                            else{
                                //larger than 1 cluster
                                int it =0;
                                it = dir->DIR_FileSize/512;
                                if(dir->DIR_FileSize%512!=0)it++;
                                for(int q = 0; q<it;q++){
                                    if(q==it-1)FAT[q+(dir->DIR_FstClusLO)]=EOF;
                                    else FAT[q+(dir->DIR_FstClusLO)]=q+dir->DIR_FstClusLO+1; //Setting every element to the next one until we reach end
                                }
                            }
                            FAT=(int*)(mappedAD+(entry->BPB_BytsPerSec*entry->BPB_RsvdSecCnt)+((entry->BPB_FATSz32*entry->BPB_BytsPerSec)*(m)));
                        }
                        
                    }
                    
                }
                
                count++;
                if(count==((entry->BPB_BytsPerSec*entry->BPB_SecPerClus)/32)){
                    count=0;
                    //Every entry is 32 bytes so we know the total number of enteries per cluster
                    prevRootClus=FAT[prevRootClus]; 
                    buff=(entry->BPB_RsvdSecCnt)*(entry->BPB_BytsPerSec) + (((entry->BPB_NumFATs) * (entry->BPB_FATSz32))*entry->BPB_BytsPerSec) + (entry->BPB_SecPerClus*entry->BPB_BytsPerSec*(prevRootClus-2));
                    dir=(DirEntry *)(mappedAD+buff);
                }   
                else{
                    buff+=0x20; //Size of 1 cluster 0x20 = 32 byte :)
                    dir=(DirEntry *)(mappedAD+buff);
                }
                name=malloc(0);
                end=malloc(0);
            }
            if(found == -1){
                printf("%s: file not found\n",argv[3]);
            }
        }
        else{
            //Request was formatted correctly. Now try to look for the file
            int prevRootClus=entry->BPB_RootClus;
            int buff = x;
            int count=0;
            int found =-1;
            int directory=0;
            
            char* name=malloc(0*sizeof(char));
            char* end=malloc(0*sizeof(char));
            dir=(DirEntry*)(mappedAD+buff);
            char* temp=malloc(strlen(argv[3]));
            strcpy(temp,argv[3]);
            temp[strcspn(temp, "\r\n")] = 0; //Remove '\0' from temp so strcmp works
            
            //Iterate through files
            while(dir->DIR_Name[0]!=0x00){
                //Format file name
                for(int i=0;i<=7;i++){
                    if(dir->DIR_Name[i]==' ')break;
                    name=realloc(name,i+1);
                    name[i]=dir->DIR_Name[i];
                    
                }
                for(int i = 0;i<3;i++){
                    if(dir->DIR_Name[i+8]==' ')break;
                    end=realloc(end,i+1);
                    end[i]=dir->DIR_Name[i+8];
                    
                }
                if(strlen(end)>0){
                    name=realloc(name,strlen(end)+1);
                    strcat(name,".");
                    strcat(name,end);
                }
                name[0]=argv[3][0];
                name[strcspn(name, "\r\n")] = 0;
                if(strcmp(temp,name)==0 && (dir->DIR_Name[0]==0xe5)){
                    directory=buff;
                    found++;
                }
                name=malloc(0);
                end=malloc(0);
                count++;
                if(count==((entry->BPB_BytsPerSec*entry->BPB_SecPerClus)/32)){
                    count=0;
                    //Every entry is 32 bytes so we know the total number of enteries per cluster
                    prevRootClus=FAT[prevRootClus]; 
                    buff=(entry->BPB_RsvdSecCnt)*(entry->BPB_BytsPerSec) + (((entry->BPB_NumFATs) * (entry->BPB_FATSz32))*entry->BPB_BytsPerSec) + (entry->BPB_SecPerClus*entry->BPB_BytsPerSec*(prevRootClus-2));
                    dir=(DirEntry *)(mappedAD+buff);
                }   
                else{
                    buff+=0x20; //Size of 1 cluster 0x20 = 32 byte :)
                    dir=(DirEntry *)(mappedAD+buff);
                }
            }
            if(found==-1){
                printf("%s: file not found\n",argv[3]);
            }
            else if(found==0){
                dir=(DirEntry *)(mappedAD+directory);
                FAT = (int *)(mappedAD+(entry->BPB_BytsPerSec*entry->BPB_RsvdSecCnt));
                printf("%s: successfully recovered\n",argv[3]);
                dir->DIR_Name[0]=argv[3][0];
                //Change *ALL* FATs
                for(int m=0;m<entry->BPB_NumFATs;m++){
                    //ASSUMED TO BE CONTIGUOSLY ALLOCATED! :)
                    if(dir->DIR_FileSize<512)FAT[dir->DIR_FstClusLO+2]=0x0ffffff8; //Smaller than 1 cluster!
                    else{
                        //larger than 1 cluster
                        int it =0;
                        it = dir->DIR_FileSize/512;
                        if(dir->DIR_FileSize%512!=0)it++;
                        for(int q = 0; q<it;q++){
                            if(q==it-1)FAT[q+(dir->DIR_FstClusLO)]=EOF;
                            else FAT[q+(dir->DIR_FstClusLO)]=q+dir->DIR_FstClusLO+1; //Setting every element to the next one until we reach end
                        }
                    }
                    FAT=(int*)(mappedAD+(entry->BPB_BytsPerSec*entry->BPB_RsvdSecCnt)+((entry->BPB_FATSz32*entry->BPB_BytsPerSec)*(m)));
                }
                
            }
            else if(found>0){
                printf("%s: multiple candidates found\n",argv[3]);
            }

        }
    }
    else if(strcmp(argv[2],"-R")==0){
        if(argc<6){
            printOptions(argv[1],argv[0]);
            return 0;
        }
        else if(strcmp(argv[4],"-s")!=0)printOptions(argv[1],argv[0]);
        else{
            int prevRootClus=entry->BPB_RootClus;
            int buff = x;
            int count=0;
            char* name=malloc(0);
            char* end=malloc(0);
            int found =-1;
            dir=(DirEntry *)(mappedAD+buff);
            
            while(dir->DIR_Name[0]!=0x00){
                
                //Format file name
                for(int i=0;i<=7;i++){
                    if(dir->DIR_Name[i]==' ')break;
                    else name[i]=dir->DIR_Name[i];
                    name=realloc(name,i+1);
                }
                for(int i = 0;i<3;i++){
                    if(dir->DIR_Name[i+8]==' ')break;
                    end[i]=dir->DIR_Name[i+8];
                    end=realloc(end,i+1);
                }
                
                if(strlen(end)>0){
                    name=realloc(name,strlen(end)+1);
                    strcat(name,".");
                    strcat(name,end);
                }
                
                name[0]=argv[3][0];
                name[strcspn(name, "\r\n")] = 0;
                
                if(strcmp(argv[3],name)==0 && (dir->DIR_Name[0]==0xe5)){
                    unsigned char* fileCONT=(mappedAD+(entry->BPB_RsvdSecCnt)*(entry->BPB_BytsPerSec) + (((entry->BPB_NumFATs) * (entry->BPB_FATSz32))*entry->BPB_BytsPerSec) + (entry->BPB_SecPerClus*entry->BPB_BytsPerSec*(dir->DIR_FstClusLO-2)));
                    unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
                    SHA1(fileCONT, dir->DIR_FileSize, hash);
                    int cH = checkHASH(hash,argv[5],SHA_DIGEST_LENGTH);
                    if(cH==1){
                        found=1;
                        FAT = (int *)(mappedAD+(entry->BPB_BytsPerSec*entry->BPB_RsvdSecCnt));
                        printf("%s: successfully recovered with SHA-1\n",argv[3]);
                        dir->DIR_Name[0]=argv[3][0];
                        //Change *ALL* FATs
                        for(int m=0;m<entry->BPB_NumFATs;m++){
                            //ASSUMED TO BE CONTIGUOSLY ALLOCATED! :)
                            if(dir->DIR_FileSize<512)FAT[dir->DIR_FstClusLO+2]=0x0ffffff8; //Smaller than 1 cluster!
                            else{
                                //larger than 1 cluster
                                int it =0;
                                it = dir->DIR_FileSize/512;
                                if(dir->DIR_FileSize%512!=0)it++;
                                for(int q = 0; q<it;q++){
                                    if(q==it-1)FAT[q+(dir->DIR_FstClusLO)]=EOF;
                                    else FAT[q+(dir->DIR_FstClusLO)]=q+dir->DIR_FstClusLO+1; //Setting every element to the next one until we reach end
                                }
                            }
                            FAT=(int*)(mappedAD+(entry->BPB_BytsPerSec*entry->BPB_RsvdSecCnt)+((entry->BPB_FATSz32*entry->BPB_BytsPerSec)*(m)));
                        }
                        
                    }
                }
                count++;
                if(count==((entry->BPB_BytsPerSec*entry->BPB_SecPerClus)/32)){
                    count=0;
                    //Every entry is 32 bytes so we know the total number of enteries per cluster
                    prevRootClus=FAT[prevRootClus]; 
                    buff=(entry->BPB_RsvdSecCnt)*(entry->BPB_BytsPerSec) + (((entry->BPB_NumFATs) * (entry->BPB_FATSz32))*entry->BPB_BytsPerSec) + (entry->BPB_SecPerClus*entry->BPB_BytsPerSec*(prevRootClus-2));
                    dir=(DirEntry *)(mappedAD+buff);
                }   
                else{
                    buff+=0x20; //Size of 1 cluster 0x20 = 32 byte :)
                    dir=(DirEntry *)(mappedAD+buff);
                }
                name=malloc(0);
                end=malloc(0);
                
            }
            if(found == -1){
                printf("%s: file not found\n",argv[3]);
            }
        }
    }
    else if(argc>7){
        printOptions(argv[1],argv[0]);
        return 0;
    }
    int numFAT=0;
    int byteSEC=0;
    int secCLUS=0;
    int resSEC=0;
    
    if(strcmp(argv[2],"-i")==0){

        numFAT=entry->BPB_NumFATs;
        byteSEC=entry->BPB_BytsPerSec;
        secCLUS=entry->BPB_SecPerClus;
        resSEC=entry->BPB_RsvdSecCnt;

        systemInfo(numFAT,byteSEC,secCLUS,resSEC);
        
    }
    else if(strcmp(argv[2],"-l")==0){
        FAT= (int *)(mappedAD+(entry->BPB_BytsPerSec*entry->BPB_RsvdSecCnt));
        int prevRootClus=entry->BPB_RootClus;
        int buff = x;
        int count=0,countREAL=0;
        char* name=malloc(0);
        char* end=malloc(0);
        dir=(DirEntry *)(mappedAD+buff);
        while(dir->DIR_Name[0]!=0x00 && (FAT[prevRootClus]!=EOF || FAT[prevRootClus]<0xffffff8)){
            if(dir->DIR_Name[0]!=0xe5){
                for(int i=0;i<=7;i++){
                    if(dir->DIR_Name[i]==' ')break;
                    name=realloc(name,i+1);
                    name[i]=dir->DIR_Name[i];
                }
                for(int i = 0;i<3;i++){
                    if(dir->DIR_Name[i+8]==' ')break;
                    end=realloc(end,i+1);
                    end[i]=dir->DIR_Name[i+8];
                }
                if(dir->DIR_Attr==0x10){
                    //Directory
                    printf("%s/ (starting cluster = %d)\n",name,dir->DIR_FstClusLO);
                }
                else if(dir->DIR_FileSize==0){
                    //Empty :)
                    if(strlen(end)==0)printf("%s (size = %d)\n",name,dir->DIR_FileSize);
                    else printf("%s.%s (size = %d)\n",name,end,dir->DIR_FileSize);
                }
                else{
                    if(strlen(end)==0)printf("%s (size = %d, starting cluster = %d)\n",name,dir->DIR_FileSize,dir->DIR_FstClusLO);
                    else printf("%s.%s (size = %d, starting cluster = %d)\n",name,end,dir->DIR_FileSize,dir->DIR_FstClusLO);
                }
                name=malloc(0);
                end=malloc(0);
                countREAL++;
            }
            count++;
            if(count==((entry->BPB_BytsPerSec*entry->BPB_SecPerClus)/32)){
                count=0;
                //Every entry is 32 bytes so we know the total number of enteries per cluster
                prevRootClus=FAT[prevRootClus]; 
                buff=(entry->BPB_RsvdSecCnt)*(entry->BPB_BytsPerSec) + (((entry->BPB_NumFATs * entry->BPB_FATSz32)*entry->BPB_BytsPerSec)) + (entry->BPB_SecPerClus*entry->BPB_BytsPerSec*(prevRootClus-2));
                dir=(DirEntry *)(mappedAD+buff);
            }
            else{
                buff+=0x20;
                dir=(DirEntry *)(mappedAD+buff);
            }
        } 
        printf("Total number of entries = %d\n",countREAL);    
    }
    munmap(entry,size.st_size);
    close(file);
    return 0;
}